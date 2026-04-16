# Novastar VX1000 Protocol — Project Context for Claude

This file is read automatically at session start. It reflects the current state of the reverse-engineering effort and all code in this repo. Read this before doing anything else.

**Last updated:** 2026-04-15 (Session 4 complete)
**Full protocol reference:** `docs/vx1000-protocol-complete.md`
**Plain-English protocol doc:** `docs/novastar-tile-protocol.md`

---

## What This Project Is

Reverse-engineering the Novastar VX1000 LED processor data port protocol. Goal: build a Mac tool (NovaTool) that can control LED tiles (brightness, test patterns, pixel injection) without a VX1000.

Hardware is inline — the Mac sits between the VX1000 and the tile. **VX1000 firmware: V2.5.0** (all captures in this project are from this version):

```
VX1000 data port 1
        │
       en11  (Mac USB NIC, MAC c8:a3:62:b0:24:72)  ← VX1000 side
        │
    [ bridge0 ]  ← macOS Layer 2 bridge, no IP
        │
       en9   (Mac USB NIC, MAC 4c:ea:41:64:67:d8)  ← tile side
        │
LED tile (Novastar A5S receiving card)
  │
  └── [optional] Tile 2 daisy-chained (same stream, no addressing)
```

---

## File Storage Convention

| Type | Location |
|---|---|
| **Capture files** (pcapng) | `~/Library/CloudStorage/Dropbox-Personal/_Claude/novastar-captures/` |
| **Scripts + docs** | `/Users/jedgerly/novastar-diagnostic/` (this repo) |
| **GitHub mirror** | `ibkickinit/Claude` → `novastar/` folder (scripts + docs only, no captures) |
| **RCFG export** | `~/Downloads/NovaTool RCFG Readback 1.rcfgx` (ZIP: XML + BIN) |
| **Legacy captures** | `~/Desktop/` (Sessions 1–3; not moved) |

`tap_capture.py` defaults `--out` to the Dropbox captures folder. Always use this for new captures. Captures are too large for GitHub — Dropbox only.

---

## Protocol Status (as of Session 4, 2026-04-15)

| Frame type | Dst MAC | Rate | Status |
|---|---|---|---|
| Pixel data | `09:1e:RR:GG:BB:RR` | ~1,530/sec | ✅ Fully decoded |
| Sync/blank | `09:1e:00:00:00:00` | ~170/sec | ✅ Fully decoded |
| Display config | `09:2d:XX:XX:XX:XX` | 1–5/sec; burst ~60fps at tile connect | ✅ Structure decoded (Session 4). Injection attempted, tile stays black without VX1000 — root cause TBD. |
| Brightness (set) | `09:3c:01:ff:ff:ff` | ~17/sec during dial movement only | ✅ Fully decoded + injection verified |
| Brightness (keepalive) | `09:3c:01:00:00:00` | ~1 per 14 sec, always | ⚠️ Periodic, role unknown |
| Gamma LUT write | `09:3c:01:00:ff:ff` etype=`0x0002` | on Save to Hardware | ✅ Decoded Session 4 — 256-entry 16-bit LUT |
| Color temp write | `09:3c:01:00:ff:ff` etype=`0x0100` | on Save to Hardware | ⚠️ Partially decoded Session 4 |
| RCFG readback | `09:5a:00:02:XX:XX` | on LCT readback | ✅ Discovered Session 4 — 63 register records × 8 bytes |
| RCFG write | `09:5a:00:01:XX:XX` | on Save to Hardware | ✅ Discovered Session 4 — shorter write format |

---

## 09:2d — FULLY DECODED (Session 4)

Rotating 24-phase sequence. Two frame types:

**NULL frames** (majority):
```
dst: 09:2d:HI:~HI:00:ff   (HI = counter byte, advances +7 each frame)
src: 00:00:00:00:00:00
etype: 0x0000
payload: all zeros (1012 bytes)
```

**DATA frames** (1 per ~6 null frames in normal mode):
```
dst: 09:2d:HI:~HI:00:ff
src: 00:ff:00:ff:00:ff
etype: comp_pair(BASE_SEQ[phase])
payload: comp_pair(BASE_SEQ[(phase+1+k) % 24]) × 506 pairs (1012 bytes)
phase advances 0→23→0 with each data frame
```

```python
BASE_SEQ = [
    0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x80,
    0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
]
# Non-zero values encode tile topology (from RCFG XML):
# 0xC0=192 = cabinet height/width
# 0x80=128 = row zone boundary (half panel)
# 0x40=64  = quarter panel
# 0x06=6   = data groups per module (96H ÷ 16-row scan)
# 0x05=5   = data groups - 1
# 0x03=3   = DataGroup value (RCFG XML)
# 0x02=2   = ModuleCols = ModuleRows (2×2 grid)
# 0x01=1   = base unit
```

**Self-test mode trigger** (NEW Session 4):
- Send one DATA frame with src=`00:ff:00:ff:00:ff`, etype=`0x00ff`, payload=all `00:ff` pairs
- Each such frame advances the tile's internal test mode counter by 1
- Sequence: Normal→Red→Green→Blue→White→Horizontal→Vertical→Slash→256 Gray→Ageing→Normal→...
- VX1000 sends ONLY these all-00ff data frames (no topology frames) during self-test

---

## 09:3c — All Subtypes

### Brightness Set (known)
```
Dst MAC: 09:3c:01:ff:ff:ff
Src MAC: 01:00:01:00:00:02
Etype:   0x0100
payload[0] = int(pct * 255 / 100)   ← floor
payload[1] = (payload[0] + 3) & 0xFF
payload[2] = 0x04 if payload[0] >= 0xFD else 0x03
payload[3] = 0x67  (fixed)
payload[4] = 0x04  (fixed)
payload[5:] = 0x00 × 1003
Total: 1022 bytes
```
Verified: 8%=0x11, 25%=0x3f, 50%=0x7f, 75%=0xbf

### Brightness Keepalive (role unknown)
```
Dst MAC: 09:3c:01:00:00:00   ← bytes 3-5 = 0x00
Payload: 1e 00 0d 67 04 00...  (does NOT follow +3 formula)
Rate: every ~14s
```

### Gamma LUT Write (NEW Session 4)
```
Dst MAC: 09:3c:01:00:ff:ff   ← byte 3 = 0x00, bytes 4-5 = ff:ff
Src MAC: 01:00:00:00:00:05
Etype:   0x0002
Payload: 256-entry × 16-bit LE gamma LUT, scale 0–8192 (GrayDepth=13)
         Table starts at payload offset 0, zero-padded to 1008 bytes
Sent 3× (once per R/G/B channel) on Save to Hardware
```
Example at gamma≈2.3: `[0, 0, 0, 1, 1, 2, 3, 4, 6, 7, 9, 11, 13, 16, 18, 21...]` → `[...7991, 8058, 8125, 8192]`

### Color Temp / Channel Gain Write (NEW Session 4 — partially decoded)
```
Dst MAC: 09:3c:01:00:ff:ff   ← same as gamma
Src MAC: 01:00:05:00:00:02
Etype:   0x0100
Payload: fe 06 03 00...  (4-byte header + data TBD)
         Non-zero bytes at offsets 46+ form a gain/LUT table
```
Need differential capture (two different color temps) to decode channel mapping.

---

## 09:5a — RCFG Protocol (NEW Session 4)

### Readback (query + response)
```
Query:    dst=09:5a:00:02:ff:59  src=varies  etype=varies  len=542
          Payload: 528 bytes (noisy — challenge/nonce?)
Response: dst=09:5a:00:02:9e:a0  len=542
          Payload: 63 records × 8 bytes + 24 zero padding
          Record format: [addr 4B][0x08][0x02][value 2B]
          (register address + data width + register value)
```
Triggered by LCT "Readback" command. Captured in `rcfg_readback.pcapng`.

### Write (Save to Hardware — color/gain)
```
dst=09:5a:00:01:XX:XX  src=04:06:06:01:04:06  etype=0x0957  len=286
Payload 272 bytes; at offset 0x16: XX DD XX 33 06... (likely R/G/B gains)
```
Byte 3 of dst MAC: 0x01=write, 0x02=readback.

---

## RCFG XML Key Values (from `NovaTool RCFG Readback 1.rcfgx`)

```
ScanBoardName:        A5S
Width × Height:       192 × 192
ModulePixelCols/Rows: 96 × 96
ModuleCols × Rows:    2 × 2 (4 modules total)
ScanType:             Scan_32
DataGroup:            3
PhysicalDataGroupNum: 12
LogicalDataGroupNum:  16
DataGroupOutputType:  Group24
RefNumPerVs:          64
GrayDepth:            13
SubFields:            8
GCLKRate:             6
GCLKPhase:            5
GCLKDuty:             3
DclkUnitCycle:        32
DclkPhase:            2
DclkHigh:             16
LineScanTime:         5
BlankUnitNumPerScan:  27
ShiftUnitNum:         96
PointNumberPerDriver: 96
TotalUnitNum:         125
ChipCode:             81 (= ICND2153)
DecType:              DecodeICN2018_ICN2019
GammaValue:           23  (≈ gamma 2.3)
RedGain/GreenGain/BlueGain: 334 (neutral)
```

---

## Tile Geometry — VERIFIED Session 3

- **Tile size:** 192 × 192 pixels physical (A5S receiving card)
- **Active pixel stream:** 187 columns wide (physical cols 4–190)
- **Left hardware columns:** 4 (physical cols 0–3, never in pixel stream)
- **Right hardware column:** 1 (physical col 191, never in pixel stream; green during RGB patterns, red during checkerboard)
- **1 Ethernet frame = 1 display row** (187 pixels = 561 bytes payload, 575 bytes total)
- **Scan order:** horizontal raster, left-to-right
- **Fixed internal zone boundaries:** col 124 (pixel stream) / row 128 — used by ALL multi-zone test patterns

---

## Test Pattern Encoding — VERIFIED Session 3

**VX1000 processor test patterns** are pixel-streamed via 09:1e.

**LCT self-test modes** are controlled via 09:2d (tile's internal patterns — no pixel stream needed).

| Pattern | Left cols (stream 0–123) | Right cols (stream 124–186) | Top rows (0–127) | Bottom rows (128–191) |
|---|---|---|---|---|
| RGB-V | White (0xbf each) | Red (R=0xbf, G=B=0) | — | — |
| RGB-H | White | White | White | Red |
| Checkerboard | White/Black alternating by row group | Inverse | White-left | Black-left |
| White Gradient V | Ramp 0x06→0xbe (1.5/px) | Ramp resets at zone boundary | (all rows identical) | — |

---

## Multi-Tile / Daisy-Chain — VERIFIED Session 3

- VX1000 is completely unaware of downstream tiles. Same stream goes to all.
- Data-connect only (tile already powered): zero disruption, zero VX1000 reaction.
- Tile power-on: brief en9 link drop (~200ms) as tile initializes; bridge loop spike after recovery.
- **Tile sends one 09:2d "ready" frame toward VX1000 on power-on** — src `00:ff:00:ff:00:ff`, all-zero complementary payload. Only tile-originated Novastar frame ever observed.
- Brightness is per-tile. Always inject 09:3c at startup to normalize the chain.
- 09:3c flows through all tiles in chain; one command syncs all.

---

## Quick Config — FAILS with bridge0 in path

Quick Config is bidirectional. The tile must ACK each phase. Mac USB NIC latency causes tile response to arrive too late → "Sync Failed" on VX1000 display.
**Fix: `sudo ifconfig bridge0 destroy` before running Quick Config, restore afterward.**

---

## Pixel Injection — UNRESOLVED (Session 4)

`inject_pattern.py` + `inject_092d.py` on en9 with bridge0 down: tile indicator light did NOT flash (zero signal recognition). Frame format verified correct against captures. Possible causes:
- Tile needs 09:5a RCFG write before it accepts pixel frames from scratch
- 09:2d injection rate too slow (VX1000 bursts at ~60fps at connect; we send 4fps)
- Some other initialization sequence required

**Test needed:** Run `inject_brightness.py` alone with bridge0 DOWN — verifies BPF injection reaches tile without bridge in path.

---

## Scripts

| Script | Purpose | Notes |
|---|---|---|
| `tap_capture.py` | Dual-iface BPF capture → pcapng | Default output: Dropbox captures folder. 1MB BPF buffer. |
| `brightness_hunt.py` | Live 09:3c capture + analysis | **Only reliable tool for 09:3c frames.** tap_capture.py drops them. |
| `decode_control.py` | Decode pcapng control frames | `--prefix 092d --iface 0`, `--prefix 093c --unique`, `--prefix 095a` |
| `color_map.py` | Live frame type tracker | Flags low-freq frames as `*** CONTROL` |
| `selective_bridge.py` | Software bridge with frame filtering | Requires `bridge0 destroy` first |
| `inject_brightness.py` | Inject 09:3c brightness frames | `--level 50`, `--sweep 0 100 5`. Injection verified working. |
| `inject_092d.py` | Inject 09:2d display config frames | Full rotating 24-phase sequence. `--self-test` mode TBD. |
| `inject_pattern.py` | Inject 09:1e pixel frames | Solid color injection. Tile not responding without VX1000. Unresolved. |

### Key Commands

```bash
# Bridge setup
sudo ifconfig bridge0 create && sudo ifconfig bridge0 addm en11 addm en9 && sudo ifconfig bridge0 up

# Pixel/pattern capture (output defaults to Dropbox captures folder)
sudo python3 tap_capture.py --mgmt-iface en11 --tile-iface en9 \
  --out ~/Library/CloudStorage/Dropbox-Personal/_Claude/novastar-captures/FILENAME.pcapng

# Brightness capture (ONLY reliable method for 09:3c)
sudo python3 brightness_hunt.py live --iface en11 \
  --out ~/Library/CloudStorage/Dropbox-Personal/_Claude/novastar-captures/FILENAME.pcapng

# Decode 09:2d by interface (0=VX1000 side, 1=tile side)
sudo python3 decode_control.py --prefix 092d --iface 0 PATH/TO/FILE.pcapng

# Decode 09:5a RCFG frames
sudo python3 decode_control.py --prefix 095a --iface 0 --max-payload 528 PATH/TO/FILE.pcapng

# Inject brightness (no VX1000 needed — works with bridge0 up)
sudo python3 inject_brightness.py --level 75

# Remove bridge before Quick Config
sudo ifconfig bridge0 destroy
```

---

## Known Bugs / Gotchas

1. **tap_capture.py cannot reliably capture 09:3c frames** — Even with 1MB BPF buffer, use `brightness_hunt.py live` for brightness work. It has a tighter read loop.
2. **BPF buffer on bridge0 is 4096 bytes** — Always capture on `en9` or `en11` directly, never on `bridge0`.
3. **09:3c only appears during brightness changes** — Static captures will always show 0 09:3c frames. This is expected.
4. **bridge0 + selective_bridge.py conflict** — Destroy `bridge0` before running `selective_bridge.py`.
5. **IDB block type in tap_capture.py pcapng** — Writes type `0x00000002` instead of `0x00000001`. Readers fall back to default microsecond timestamps. Harmless but non-standard.
6. **Threading exception on Ctrl+C** — tap_capture.py throws a daemon thread stderr error on exit. File is saved correctly before the exception. Harmless.
7. **VX1000 shows no pixel data after cold boot** — Must manually re-enable test pattern from VX1000 UI. VX1000 boots into sync-only mode.

---

## Open Questions (Session 4)

1. **Pixel injection from scratch** — inject_pattern.py + inject_092d.py don't light tile without VX1000. Test inject_brightness.py alone with bridge0 down first.
2. **09:2d cold-start initialization** — Does tile need a burst at ~60fps before accepting pixel data? Does it need 09:5a RCFG write first?
3. **09:5a register format** — 63 records, bytes 0–3=address, 4=0x08, 5=0x02, 6–7=value. Address encoding TBD. Need differential capture (change one param, compare responses).
4. **Color temp channel mapping** — `09:3c:01:00:ff:ff` write has 4 bytes at offset 0x16 of 09:5a save frame. Need 2nd color temp capture at different value to decode R/G/B channel order.
5. **09:3c keepalive role** — `09:3c:01:00:00:00`, every 14s. Status report? Tile keepalive? Unknown.
6. **Short sync frames (132/136/496 bytes)** — Appear scattered after VX1000 boot. Cause unknown.
7. **Row scan direction** — L→R confirmed; top→bottom unconfirmed.
8. **VX1000 port 2** — Same frame prefixes as port 1? Not tested.

---

## Captures on File

**Session 4 captures:** `~/Library/CloudStorage/Dropbox-Personal/_Claude/novastar-captures/`
**Legacy captures (Sessions 1–3):** `~/Desktop/` — not moved, still accessible

| File | Location | Key content |
|---|---|---|
| `rcfg_readback.pcapng` | Dropbox | **09:5a readback frames — RCFG register map** |
| `gamma_sweep_1_to_4.pcapng` | Dropbox | **09:3c gamma LUT write frames; 256-entry 16-bit table** |
| `color_temp_6500_to_4500.pcapng` | Dropbox | **09:3c color temp write + 09:5a save; channel mapping TBD** |
| `self_test_modes.pcapng` | Dropbox | **09:2d self-test mode advance; all-00ff trigger frames** |
| `vx1000_session.pcapng` | Desktop | Session 1, 4.9M frames — pixel stream confirmed |
| `vx1000_session2.pcapng` | Desktop | Session 2 — 09:2d frames spotted |
| `static_0pct.pcapng` | Desktop | 0% brightness static baseline |
| `static_100pct.pcapng` | Desktop | 100% brightness static baseline; 09:2d BASE_SEQ source |
| `static_49pct.pcapng` | Desktop | 49% brightness static baseline |
| `en11_bounce.pcapng` | Desktop | 225 09:3c frames — the brightness decode source |
| `quickconfig_attempt.pcapng` | Desktop | Two Quick Config attempts — 09:2d bidirectional; bridge0 latency causes fail |
| `brightness_8pct.pcapng` | Desktop | 16 09:3c frames; payload[0]=0x11 |
| `brightness_25pct.pcapng` | Desktop | 27 09:3c frames; settled at 0x3f |
| `brightness_50pct.pcapng` | Desktop | 25 09:3c frames; settled at 0x7f |
| `brightness_75pct.pcapng` | Desktop | 24 09:3c frames; settled at 0xbf |
| `test_patterns_all.pcapng` | Desktop | All solid colors confirmed pixel-streamed; 575-byte frames |
| `pattern_rgbv.pcapng` | Desktop | RGB-V; col boundary=124; white/red split; scan=horizontal raster |
| `pattern_rgbh.pcapng` | Desktop | RGB-H; 1 frame/row; 128 white + 64 red rows; green col=hardware |
| `pattern_checkerboard.pcapng` | Desktop | Checkerboard; 2×2 blocks; col/row boundaries = 124/128 |
| `pattern_gradient_white_v.pcapng` | Desktop | White gradient V; Bresenham 1.5/px; start=0x06 confirms 4 left HW cols |
| `powercycle_init.pcapng` | Desktop | Tile power cycle; VX1000 streams continuously; 09:2d burst at reconnect |
| `powercycle_vx1000.pcapng` | Desktop | VX1000 cold boot; ~40s boot; sync-only at boot; 09:3c keepalive every ~14s |
| `daisy_chain_tile2.pcapng` | Desktop | Two tiles daisy-chained; VX1000 unaware; same stream; brightness per-tile |
| `daisy_tile2_poweron.pcapng` | Desktop | Tile 2 powered on; en9 link drop 200ms at t=3s; tile-originated 09:2d at t=0.265s |

---

## Repos

| Repo | Purpose |
|---|---|
| `ibkickinit/novastar-tile-tool` | This repo — all capture/analysis scripts + docs |
| `ibkickinit/novastar-demo` | NovaTool UI demo (index.html) — no changes this session |
| `ibkickinit/Claude` → `novastar/` | Cross-session memory mirror — scripts + docs only (no captures) |

GitHub PAT is in memory file `reference_github.md`.
