# VX1000 Data Port Protocol Capture &mdash; 2026-04-15

**Status:** COMPLETE  
**Hardware:** VX1000 processor, single LED tile (Novastar A8 receiving card)  
**Operator:** Justin Edgerly  
**Goal:** Passively capture and decode the raw data protocol between VX1000 port 1 output and a connected LED tile.

> **Full narrative and protocol spec:** see [`vx1000-protocol-complete.md`](vx1000-protocol-complete.md)

---

## Hardware Setup

| Device | Role | Interface / IP |
|---|---|---|
| VX1000 processor | Source | Data port 1 &rarr; Mac en11 (c8:a3:62:b0:24:72) |
| Mac (bridge) | Inline tap | bridge0 (en11 + en9) |
| LED tile | Sink | Mac en9 (4c:ea:41:64:67:d8) &rarr; tile |
| VX1000 management | Not connected this session | 192.168.0.10 (data only) |

Direct VX1000&rarr;tile cable confirmed working before bridge was inserted (tile lit up).

---

## Bridge Setup

macOS Layer 2 bridge, no IP address needed &mdash; pure L2 passthrough.

```bash
sudo ifconfig bridge0 create
sudo ifconfig bridge0 addm en11 addm en9
sudo ifconfig bridge0 up
```

Verified result:

```
bridge0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>
    member: en11 flags=3<LEARNING,DISCOVER>
    member: en9  flags=3<LEARNING,DISCOVER>
    status: active
```

Address cache showed MAC entries learning on en11 within seconds of bridge coming up. Tile came live through the bridge immediately. Minor flicker observed &mdash; expected due to USB NIC jitter and macOS bridge latency on a time-sensitive pixel stream. Not a problem for passive capture purposes.

---

## Capture Tool

Script: `/Users/jedgerly/novastar-diagnostic/tap_capture.py`

Python 3.9 compatibility fixes applied (replaced `X | None` union syntax with `Optional[X]` from `typing`).

VX1000 tile MAC addresses added (replacing TB10-only `09:87:00:00:00:00`):

```python
NOVA_TILE_DSTS = {
    bytes.fromhex('091ebfbfbfbf'): 'pixel',   # VX1000 pixel data frames
    bytes.fromhex('091e00000000'): 'sync',    # VX1000 sync/control frames
    bytes.fromhex('098700000000'): 'pixel',   # TB10 legacy (kept for compat)
}
```

Session 1 capture: `~/Desktop/vx1000_session.pcapng` (4.9M frames, ~2 min)  
Session 2 capture: `~/Desktop/vx1000_session2.pcapng` (confirmed tile frame decode working)

---

## Protocol Findings

### Frame types on the wire

Two frame types observed (confirmed via pcapng analysis and live color_map.py output):

| Type | Dst MAC | Ethertype | Src MAC | Payload |
|---|---|---|---|---|
| Pixel data | `09:1e:RR:GG:BB:RR` | `0xRRGG` | follows stream | raw RGB stream |
| Sync | `09:1e:00:00:00:00` | `0x0000` | `00:00:00:00:00:00` | all zeros |

A third low-frequency frame type (`09:2d:XX:XX:XX:XX`) observed in first capture &mdash; appears at control/command frequency. Likely carries brightness or configuration. **Not yet decoded &mdash; open item.**

### Pixel stream encoding &mdash; KEY FINDING

**The VX1000 streams raw pixel data continuously from byte 2 of the Ethernet frame. The MAC addresses and ethertype are NOT conventional Ethernet fields &mdash; they are simply bytes 2&ndash;13 of the pixel stream, with a fixed `09:1e` header at bytes 0&ndash;1.**

Full frame layout:

```
Byte:  0    1    2    3    4    5    6    7    8    9   10   11   12   13   14  15  16 ...
       09   1e  [R0  G0   B0   R1] [G1   B2   R2   G2   B2   R3] [G3  B3] [R4  G4  B5 ...]
                ^--- dst MAC bytes 2-5 ---^  ^-------- src MAC --------^  ^etype^ ^payload^
                ^----------------------- continuous pixel stream from byte 2 ------------------^
```

Confirmed against all test patterns at 60% brightness (pixel value 0xBF = 191):

| VX1000 setting | RGB | Dst MAC bytes 2-5 | Etype |
|---|---|---|---|
| White | BF,BF,BF | BF:BF:BF:BF | 0xBFBF |
| Black | 00,00,00 | 00:00:00:00 | 0x0000 |
| Red | BF,00,00 | BF:00:00:BF | 0x0000 |
| Green | 00,BF,00 | 00:BF:00:00 | 0xBF00 |
| Blue | 00,00,BF | 00:00:BF:00 | 0x00BF |

The pattern is exact in every case: dst MAC bytes [2:6] = pixel stream bytes [0:4], ethertype = pixel stream bytes [4:6].

### Brightness encoding &mdash; **SOLVED**

**`09:3c` frames carry the brightness command.** Proven via selective software bridge (`selective_bridge.py`):
- Dropping `09:3c` → tile stays lit but brightness **never responds** to VX1000 dial changes.
- Dropping `09:2d` → tile goes **completely dark** (required for display operation, not brightness-specific).

#### 09:3c Frame Structure (complete decode)

```
Dst MAC   : 09:3c:01:ff:ff:ff        (fixed control broadcast)
Src MAC   : 01:00:01:00:00:02        (fixed deliberate control source)
Ethertype : 0x0100 (256)             (fixed control frame type)

Payload:
  [0]   brightness   — 0x00 (0%) … 0xFF (100%), 8-bit linear scale
  [1]   (brightness + 3) & 0xFF      — checksum carry byte
  [2]   0x03 normally; 0x04 when brightness ≥ 0xFD (overflow carry flag)
  [3]   0x67                          — fixed protocol byte
  [4]   0x04                          — fixed protocol byte
  [5+]  0x00 × 1003                   — zero padding to 1008 bytes total
```

#### Brightness mapping

| VX1000 setting | payload[0] | payload[1] | payload[2] |
|---|---|---|---|
| 0% | `0x00` | `0x03` | `0x03` |
| ~25% | `0x3f` | `0x42` | `0x03` |
| ~50% | `0x7f` | `0x82` | `0x03` |
| ~75% | `0xbf` | `0xc2` | `0x03` |
| ~100% | `0xff` | `0x02` | `0x04` |

#### Behavior

- `09:3c` is **event-driven**: only fires while the brightness dial is moving.
- When the dial is stationary, no `09:3c` frames are sent (confirmed: zero `09:3c` frames in static captures at 0%, 49%, and 100%).
- The tile holds the last received brightness value.
- During a sweep, the VX1000 sends intermediate values at ~17 fps, ramping `payload[0]` between the source and target levels.

#### To inject brightness from the Mac

```python
def make_093c_brightness(level_0_to_255: int) -> bytes:
    b = level_0_to_255 & 0xFF
    chk = (b + 3) & 0xFF
    carry = 0x04 if b >= 0xFD else 0x03
    payload = bytes([b, chk, carry, 0x67, 0x04]) + b'\x00' * 1003
    dst = bytes([0x09, 0x3c, 0x01, 0xff, 0xff, 0xff])
    src = bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x02])
    etype = bytes([0x01, 0x00])
    return dst + src + etype + payload
```

Inject 5–10 times over ~600 ms for reliable delivery (mirrors VX1000 behavior).

### Frame statistics

- Rate: ~1,700 tile frames/sec through the bridge
- Frame size: 959 bytes (14-byte Ethernet header + 945 bytes payload)
- 945 payload bytes = 315 RGB pixels per frame
- Pixel stream + sync mix: ~90% pixel frames, ~10% sync/zero frames

---

## Scripts (in `/Users/jedgerly/novastar-diagnostic/`)

| Script | Purpose |
|---|---|
| `tap_capture.py` | Dual-interface BPF capture → pcapng. VX1000 MACs included. |
| `color_map.py` | Live per-interval frame type tracker. Flags low-frequency control frames (`*** CONTROL`). |
| `decode_control.py` | Reads pcapng, extracts control frames by dst MAC prefix, dumps hex payloads, shows byte-level diffs. |
| `brightness_hunt.py` | Multi-mode: `diff` (transition vs baseline), `sweep` (frame type timeline), `live` (BPF + rare-frame detection). |
| `selective_bridge.py` | Software bridge replacing bridge0. Selectively drops/passes frame types for isolation testing. |
| `inject_brightness.py` | Injects 09:3c brightness frames from the Mac without a VX1000. `--level N`, `--sweep A B T`. |
| `inline_capture.py` | Earlier inline capture script (predates this session). |

---

## Open Items From This Session

1. ~~**Decode `09:2d` frames**~~ — `09:2d` is required for display operation but does **not** carry brightness. Frame content stable across all brightness levels.
2. ~~**Map brightness values**~~ — **SOLVED.** `payload[0]` = 0x00–0xFF maps directly to 0–100% brightness.
3. **Identify pixel count encoding** &mdash; 945 bytes = 315 pixels. Is this fixed or does it vary with tile resolution/config?
4. **Inject test pattern** &mdash; frame structure known; can now construct pixel frames from the Mac without a processor. See `inject_brightness.py` for the brightness-injection equivalent.
5. **Verify 25/50/75% exact values** &mdash; table above uses calculated values (level×255/100). Confirm with a targeted static capture at those exact levels.
6. **Map `09:2d` full structure** &mdash; confirmed it is required for display but its role (sync handshake? config?) is not yet decoded.

---

*Session conducted by Justin Edgerly and Claude (Anthropic), 2026-04-15*
