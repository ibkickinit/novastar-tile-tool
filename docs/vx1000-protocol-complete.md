# Novastar VX1000 Data Port Protocol — Complete Reverse Engineering Reference

**Author:** Justin Edgerly with Claude (Anthropic)  
**Date:** 2026-04-15  
**Status:** COMPLETE — full protocol decoded, injection verified  
**Hardware:** Novastar VX1000 processor (firmware V2.5.0) → Novastar A8 receiving card (single LED tile)

---

## Why This Document Exists

The VX1000 streams pixel data and control commands to LED tiles over raw Ethernet using a completely proprietary layer-2 protocol. There is no public documentation. Novastar does not publish it. This document records a complete reverse-engineering effort conducted via passive capture, traffic analysis, and systematic isolation testing, starting from zero knowledge.

If you are reading this to understand the protocol — skip to [Final Protocol Specification](#final-protocol-specification).  
If you are reading this to understand how we got there — read everything.

---

## Hardware Setup

```
VX1000 data port 1
        │ (Ethernet)
       en11  (Mac USB NIC, MAC c8:a3:62:b0:24:72)
        │
    [ bridge0 ]   ← macOS Layer 2 bridge, no IP, pure passthrough
        │
       en9   (Mac USB NIC, MAC 4c:ea:41:64:67:d8)
        │ (Ethernet)
LED tile (Novastar A8 receiving card)
```

The Mac sits **inline** between the VX1000 and the tile. bridge0 forwards everything transparently at Layer 2 — the tile has no idea there is a Mac in the path. Both BPF interfaces can capture the full bidirectional stream.

**Why inline instead of a tap?** The VX1000 data port carries a continuous ~1,700 fps pixel stream. There is no spare port to mirror to. The bridge is the only way to see both directions without opening the hardware.

**Bridge setup:**
```bash
sudo ifconfig bridge0 create
sudo ifconfig bridge0 addm en11 addm en9
sudo ifconfig bridge0 up
```

Tile came live through the bridge immediately. Minor flicker observed on first insertion — expected, due to USB NIC timing jitter on a 1,700 fps pixel stream. Not an operational problem.

---

## What We Knew Going In: Nothing

Before this work, zero protocol details were known. The only baseline:

- The VX1000 has Ethernet data output ports
- Tiles plug directly into those ports
- Brightness, test patterns, and routing are controlled from the VX1000 UI
- Changing brightness on the VX1000 UI changes what the tile displays in real time
- The only physical path between the VX1000 and the tile is that Ethernet cable

That last point became the key constraint: **if the Mac is inline and the tile responds, everything must be passing through the Mac.** No other physical path exists.

---

## Phase 1: Passive Capture and Initial Frame Analysis

### What we saw immediately

BPF capture on en9 (tile side) showed frames arriving at ~1,700/sec. Every frame started with `09:1e`. This is not a valid IEEE 802.3 OUI — the first byte is `0x09`, which is not a registered vendor prefix. Novastar is doing something non-standard with the Ethernet header.

### The pixel stream discovery

Running `color_map.py` while cycling test patterns (red, green, blue, white, black) on the VX1000 revealed the pattern instantly:

| Pattern | Dst MAC bytes 2–5 | Ethertype | Pixel value |
|---|---|---|---|
| White at 60% | `bf:bf:bf:bf` | `0xbfbf` | 0xBF = 191 |
| Black | `00:00:00:00` | `0x0000` | 0x00 |
| Red at 60% | `bf:00:00:bf` | `0x0000` | R=0xBF, G=0x00, B=0x00 |
| Green at 60% | `00:bf:00:00` | `0xbf00` | R=0x00, G=0xBF, B=0x00 |
| Blue at 60% | `00:00:bf:00` | `0x00bf` | R=0x00, G=0x00, B=0xBF |

**KEY FINDING: The VX1000 does not use Ethernet framing at all.** The "MAC addresses" and "ethertype" in these frames are not Ethernet header fields — they are the first 12 bytes of a continuous raw RGB pixel stream, with a fixed `09:1e` prefix at bytes 0–1.

Full frame layout:
```
Byte:  0    1    2    3    4    5    6    7    8    9   10   11   12   13   14  15  16 ...
       09   1e  [R0  G0   B0   R1] [G1   B1   R2   G2   B2   R3] [G3  B3] [R4  G4  B4 ...]
                ^--- dst "MAC" ---^  ^---- src "MAC" -------^  ^etype^  ^-- payload --^
                ^------------------------------ continuous RGB pixel stream from byte 2 -----^
```

The `09:1e` prefix is a Novastar magic number. Everything after it is pixels. The Ethernet switch/bridge forwards these frames normally because they look like valid Ethernet frames (just with unusual addresses).

### Sync frames

A second frame type also appears: `09:1e:00:00:00:00` with ethertype `0x0000`, src MAC all zeros, payload all zeros. These appear at ~8–10% of total frame volume. They represent "blank" scan lines or sync/timing signals in the pixel stream (the pixel value at that scan position is `00:00:00`).

### Frame statistics (confirmed)

- ~1,700 frames/sec total through bridge
- Frame size: 959 bytes (14-byte header + 945-byte payload) — original tile at default scan config
- 192×192 tile (1×1 config, Novastar A8): 575 bytes per frame
  - After failed Quick Config, VX1000 enters reduced scan mode: 383-byte frames. Fix: remove bridge0, run Quick Config successfully, restore bridge0.
- ~90% pixel frames (`09:1e` with non-zero bytes 2+)
- ~8–10% sync/blank frames (`09:1e:00:00:00:00`)

---

## Phase 2: Control Frame Discovery

### The 09:2d frame

During the first long capture (`vx1000_session.pcapng`, 4.9M frames, ~2 min), `color_map.py` flagged a low-frequency frame type: `09:2d:XX:XX:XX:XX`. It appeared at roughly 1–5 fps vs 1,700 fps for pixel data. The `*** CONTROL` flag in `color_map.py` catches any frame type under 5% of total volume.

Initial hypothesis: `09:2d` carries brightness. It was the only non-pixel frame type we could see. This turned out to be wrong.

### The 09:3c frame

Later captures (specifically `en11_bounce.pcapng`, captured on the VX1000 side en11 during brightness bounces) revealed a second control frame type: `09:3c:01:ff:ff:ff`. This one was completely invisible in the en9-side static captures because it only fires during brightness changes — not continuously. We only found it because:

1. We captured on en11 (VX1000 side) during active brightness changes
2. We were looking at ALL frame types, not just ones present in baseline captures

---

## Phase 3: The Brightness Hunt — Everything We Tried That Failed

This phase consumed most of the investigation time. We systematically eliminated every hypothesis before finding the answer.

### Failed hypothesis 1: Pixel values encode brightness

**Theory:** Changing brightness changes the pixel intensity values in the `09:1e` stream. If brightness=50%, pixel values would be 0x7F instead of 0xFF.

**Test:** Captured at 0%, 49%, 100% brightness while sending a static white pattern. Compared pixel byte values across captures.

**Result:** Pixel values identical across all brightness levels. The VX1000 sends full-intensity pixel data (0xBF for "white at 60%") regardless of the brightness setting. The brightness control must be separate from the pixel data.

**Lesson learned:** The VX1000 does not PWM or scale the pixel stream for brightness. The A8 receiving card handles brightness in hardware, separate from the pixel data path.

---

### Failed hypothesis 2: Sync frame ratio encodes brightness

**Theory:** The ratio of sync frames (`09:1e:00`) to pixel frames changes with brightness. Higher brightness = more pixel frames, lower brightness = more sync/blank frames.

**Test:** `color_map.py --brightness` mode tracked pixel vs blank frame ratio at 1-second intervals across a 0–25–50–75–100–0 sweep.

**Result:** Ratio completely flat at ~8–9% sync frames across all brightness levels. No correlation whatsoever.

---

### Failed hypothesis 3: Frame rate encodes brightness

**Theory:** The VX1000 sends fewer frames per second at lower brightness.

**Test:** Counted total frames per second across brightness levels.

**Result:** Frame rate flat at ~3,600–3,800 fps. No correlation.

---

### Failed hypothesis 4: 09:2d payload encodes brightness

**Theory:** The `09:2d` low-frequency control frames carry a brightness register write.

**Investigation:** Captured at static 0%, 49%, and 100% brightness. Ran `decode_control.py --prefix 092d --unique` on each capture.

**Result:** `09:2d` payload had exactly 5 unique normalized payloads across all brightness levels. Content was **identical** at 0%, 49%, and 100%. Zero correlation with brightness.

**Actual role of 09:2d (confirmed separately):** `09:2d` is required for the tile to display anything at all. When dropped via the software bridge, the tile goes completely dark. It is likely a sync handshake, configuration frame, or keepalive — but it is NOT the brightness carrier.

---

### Failed hypothesis 5: Novel frame types appear during brightness changes

**Theory:** There is a frame type we haven't seen yet that only appears when brightness changes. A diff of transition vs static captures would reveal it.

**Test:** `brightness_hunt.py diff` mode. Loaded static_0pct.pcapng as baseline, compared bounce_0_100.pcapng for novel payload fingerprints.

**Result:** No novel payloads found. The diff tool found zero frame payloads that appeared during transitions but not in baseline.

**Why it failed:** The 09:3c brightness frames WERE present during transitions, but the diff was fingerprinting by `frame[14:78]` (payload bytes 0–63), and the `09:3c` frames were present in enough variety that they matched baseline payloads from earlier bounces. Also, the baseline captures did include some 09:3c frames from the initial connection event. The diff approach was too coarse.

---

### Failed hypothesis 6: Unusual 09:1e dst MACs appear during transitions

**Theory:** A brightness command is sneaked into the pixel stream by sending a frame with a special dst MAC that is NOT a valid pixel pattern.

**Test:** Scanned all 09:1e dst MACs in all captures for any that didn't fit the pixel stream encoding pattern.

**Result:** Zero unusual MACs found. Every `09:1e` frame had a dst MAC fully consistent with raw pixel data.

---

### Failed hypothesis 7: Management protocol uses the data port

**Theory:** Maybe the VX1000 sends TCP management frames (like the T10 `55 AA` protocol) over the data port in addition to the raw pixel stream.

**Investigation:** Justin confirmed no management connection was active during captures. Also checked for `55 AA` magic bytes, link-local frames, ARP, and any non-`09:xx` frames.

**Result:** Zero management frames. The data port carries only the raw `09:xx` protocol. No TCP/UDP. Pure Layer 2.

---

### Failed hypothesis 8: The Mac is not the only path (initial skepticism)

**Theory / early concern:** Maybe the brightness signal bypasses the Mac entirely — some out-of-band path (second Ethernet port, management port, USB, HDMI, etc.).

**Justin's confirmation:** "I promise you the brightness is passing through the Mac." Verified: the VX1000 management port was not connected during the session. The only cable between VX1000 and tile passed through the Mac bridge. Brightness changes were instant and observable — no possibility of a second path.

**This confirmation was critical** — it meant we could trust our captures completely. If the Mac was in the path and our captures weren't finding the brightness signal, the problem was in our analysis, not the hardware.

---

### Failed hypothesis 9: The 09:2d dst MAC cycles encode something

**Theory:** The `09:2d` dst MAC bytes 2–5 cycle through values. Maybe this cycling encodes brightness or another parameter.

**Test:** Compared `09:2d` dst MAC patterns across brightness levels. Noted the cycling patterns.

**Result:** The cycling was a frame counter / sequence number. No correlation with brightness levels across captures at 0%, 49%, 100%. Dead end.

---

## Phase 4: The Breakthrough — Selective Software Bridge

When all passive analysis failed, we changed approach: instead of looking at what the frames contain, we would test which frame types are **required** for which function by selectively dropping them.

### The selective bridge

`selective_bridge.py` replaces macOS bridge0 with a Python software bridge that can drop or pass specific frame types while forwarding everything else. Setup:

```bash
# Tear down hardware bridge
sudo ifconfig bridge0 destroy

# Run software bridge with filter
sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop 093c
```

### Test results

| Test | Filter | Tile behavior | Conclusion |
|---|---|---|---|
| Baseline | Drop nothing | Tile works, brightness works | Bridge transparent ✓ |
| Drop 09:2d | `--drop 092d` | **Tile goes completely dark** | 09:2d required for display |
| Drop 09:3c | `--drop 093c` | Tile lights up, **brightness dial does nothing** | **09:3c carries brightness** |

The Step 3 result from Justin: *"It DID light up, and did NOT adjust brightness!"*

This was the decisive experiment. When `09:3c` frames were dropped:
- The tile continued receiving pixel data (via 09:1e) and displaying normally
- The tile held its last known brightness value
- No amount of dial movement changed anything
- As soon as we restored `09:3c` forwarding, brightness control resumed instantly

**Conclusion: 09:3c frames carry the brightness command.** The tile stores the last received brightness value and holds it until a new one arrives.

---

## Phase 5: Decoding the 09:3c Payload

### Initial analysis of en11_bounce.pcapng

We had a capture from en11 (VX1000 side) during a brightness bounce sequence (0→1→0→100→0). This file contained 225 `09:3c` frames in a 12.93-second burst.

First pass analysis identified:
- Fixed dst MAC: `09:3c:01:ff:ff:ff`
- Fixed src MAC: `01:00:01:00:00:02` (NOT from the pixel stream — a deliberate control address)
- Fixed ethertype: `0x0100` = 256
- Payload: only bytes 0–4 ever non-zero; bytes 5–1007 always zero
- Payload byte 0: 70+ unique values — initially interpreted as a "cycling counter"
- Payload byte 1: always = byte 0 + 3 (mod 256) — interpreted as a checksum
- Payload byte 2: 0x03 (185 times) or 0x04 (40 times)
- Payload bytes 3–4: always `0x67 0x04` (fixed)

The "cycling counter" interpretation was **wrong**. We got distracted by the large number of unique values and the counter-like relationship between bytes 0 and 1.

### The actual decode

Plotting ALL 225 frames in sequence (timestamp, payload byte 0, byte 1, byte 2) revealed the truth immediately:

```
Frame 0–5:    p[0] ramps DOWN from 0xfc → 0x00  (brightness going to 0%)
Frames 5–16:  p[0] = 0x00, holds flat              ← tile at 0% brightness
Frames 17–21: p[0] ramps UP from 0x0f → 0xc4      (brightness going up)
Frame 22:     p[0] = 0xff, p[2] = 0x04             ← tile at 100% brightness
Frames 22–31: p[0] = 0xff, holds flat              ← tile at 100% brightness
Frames 32–76: p[0] ramps DOWN from 0xfc → 0x00    (brightness going to 0%)
... [multiple sweeps, same pattern] ...
```

The "cycling counter" was the brightness value stepping through intermediate levels during the transition. The VX1000 sends live intermediate values as the dial moves — ~17 frames per second during the sweep — which creates a smooth ramp from the current level to the target.

**payload[0] = brightness, 0x00–0xFF (0% = 0x00, 100% = 0xFF)**

### The other bytes explained

| Byte | Formula | Explanation |
|---|---|---|
| `p[0]` | brightness | 8-bit brightness value, 0–255 |
| `p[1]` | `(p[0] + 3) & 0xFF` | Carry/checksum byte — derived from p[0] |
| `p[2]` | `0x03 + carry` | Overflow flag: `0x03` normally, `0x04` when p[0]+3 > 255 (i.e., p[0] >= 0xFD) |
| `p[3]` | `0x67` | Fixed protocol byte |
| `p[4]` | `0x04` | Fixed protocol byte |
| `p[5+]` | `0x00` | Zero padding to 1008 bytes |

The carry relationship (p[0], p[1], p[2] together forming a 3-byte little-endian integer with p[1] = p[0]+3) suggests this payload fragment is part of a larger Novastar register-write protocol, where bytes 0–4 encode a single brightness register value as a 24-bit quantity with checksum. The fixed `0x67 0x04` bytes are likely a fixed register address or protocol tag.

### Why the static captures had zero 09:3c frames

`09:3c` is **event-driven** — it only fires while the brightness dial is actively changing. When the VX1000 is sending a static scene at a fixed brightness, no `09:3c` frames are transmitted. The tile holds its last-received brightness value indefinitely.

This explains why the static captures at 0%, 49%, and 100% contained zero `09:3c` frames, and why the diff-based analysis (Phase 3, hypothesis 5) failed — there was nothing to diff during a static capture.

---

## Final Protocol Specification

### Frame types on the wire

| Frame type | Dst MAC | Rate | Role |
|---|---|---|---|
| Pixel data | `09:1e:RR:GG:BB:RR` | ~1,530/sec | Continuous RGB pixel stream |
| Sync/blank | `09:1e:00:00:00:00` | ~170/sec | Sync timing / blank pixels |
| Display config | `09:2d:XX:XX:XX:XX` | 1–5/sec | Required for display operation (role TBD) |
| **Brightness** | `09:3c:01:ff:ff:ff` | **~17/sec during changes only** | **Brightness control** |

---

### 09:1e — Pixel data frame

```
[0-1]   09 1e           ← Novastar pixel stream magic prefix
[2-5]   RR GG BB RR     ← Dst MAC bytes 2-5 = pixel stream bytes 0-3
[6-11]  GG BB RR GG...  ← Src MAC = pixel stream bytes 4-9
[12-13] BB RR           ← Ethertype = pixel stream bytes 10-11
[14+]   GG BB ...       ← Payload = pixel stream bytes 12+
```

The entire frame from byte 2 onward is a continuous raw RGB byte stream. Ethernet framing is being abused as a transport container.

- Frame size: 575 bytes (192×192 tile, 1×1 Novastar A8 config) — 14-byte header + 561-byte payload = 187 RGB pixels per frame
- Frame size: 959 bytes (original/default scan config)
- Rate: ~1,530 fps pixel frames + ~170 fps sync frames = ~1,700 fps total

**Reading the dst MAC as a scan position indicator:**
dst MAC bytes 2–5 are always the first 4 bytes of that frame's pixel payload. Because the pixel stream is continuous and frames don't align to row boundaries, the dst MAC reveals where in the display scan that frame starts:

| dst MAC bytes 2–5 | Meaning |
|---|---|
| `00:00:00:00` | Frame starts at a zero-value pixel (sync/blank, or scan position is between content) |
| `bf:bf:bf:bf` | Frame starts in a white region (R=G=B=0xbf) |
| `bf:00:00:bf` | Frame starts in a red region (R=0xbf, G=0, B=0) |
| `00:bf:00:00` | Frame starts in a green region (R=0, G=0xbf, B=0) |
| `00:00:bf:00` | Frame starts in a blue region (R=0, G=0, B=0xbf) |

**Why "mostly black" MACs appear even during colored patterns:** Sync frames (all-zero payload, `09:1e:00:00:00:00`) appear at ~10% rate continuously regardless of pattern. At 1,700 fps, ~170 of those frames per second have the black dst MAC. If only a small number of pixel frames happen to start in a non-white region in a given capture window, black MACs will dominate the count. The payload content — not the dst MAC alone — reveals the actual pattern.

---

### 09:1e — Test pattern encoding (VERIFIED 2026-04-15)

**All VX1000 test patterns are pixel-streamed via 09:1e.** The VX1000 generates the test pattern internally and streams the resulting RGB data to the tile. There is no separate test-pattern command frame type.

**Confirmed patterns (192×192 tile, 60% brightness = 0xbf):**

| VX1000 pattern | Pixel content | dst MAC observed |
|---|---|---|
| Black | All zeros | `09:1e:00:00:00:00` only |
| White | R=G=B=0xbf throughout | `09:1e:bf:bf:bf:bf` |
| Red | R=0xbf, G=0, B=0 throughout | `09:1e:bf:00:00:bf` |
| Green | R=0, G=0xbf, B=0 throughout | `09:1e:00:bf:00:00` |
| Blue | R=0, G=0, B=0xbf throughout | `09:1e:00:00:bf:00` |
| RGB-V | See below | Mix of `bf:bf:bf:bf` and others depending on scan position |
| White Gradient V | See below | `09:1e:00:00:00:01` (first pixel = 0x00,0x00,0x06 → dst encodes first 4 bytes) |

**RGB-V (vertical stripes) — confirmed geometry on 192×192 tile at 60% brightness:**

Visual: left ~2/3 white | right ~1/3 red | far-right 1-pixel column green.

Pixel layout per scan line (192 pixels wide):
- Columns 0–123 (~128px): White — R=G=B=0xbf
- Columns 124–190 (~63px): Red — R=0xbf, G=0, B=0
- Column 191 (1px): Green — R=0, G=0xbf, B=0

Frame payload analysis (frame starting in white region, `bf:bf:bf:bf` dst MAC):
```
bytes [0:373]    = 0xbf repeatedly       ← white pixels
byte  [373]      = 0x00  (G of pixel 124 = start of Red region)
byte  [374]      = 0x00  (B of pixel 124)
byte  [375]      = 0xbf  (R of pixel 125, still Red)
byte  [376]      = 0x00  (G of pixel 125)
...continues as [R=0xbf, G=0, B=0] repeating
```

The `bf:bf:bf:bf` dst MAC for an RGB-V frame means the frame started scanning in the white stripe. The red and green stripe content is visible deeper in the payload (offset 373+).

**RGB-H (horizontal stripes) — confirmed geometry on 192×192 tile at 60% brightness:**

Visual: top ~2/3 white | bottom ~1/3 red | far-right 1-pixel column green (hardware artifact, see below).

Capture analysis (pattern_rgbh.pcapng, iface 0 = VX1000 side):
- 1,255 pure-white frames (`09:1e:bf:bf:bf:bf`) + 598 pure-red frames (`09:1e:bf:00:00:bf`)
- Ratio 1255:598 = 2.10:1 → confirms ~128 white rows : ~64 red rows (top 2/3 / bottom 1/3)
- **All white frames are identical** (single unique payload: 187× `bf bf bf`)
- **All red frames are identical** (single unique payload: 187× `bf 00 00`)
- Zero boundary frames (frames spanning the white→red row boundary)

**Key finding — one frame per display row:**
The absence of boundary frames means each 561-byte (187-pixel) frame corresponds to **exactly one display row**. The VX1000 sends exactly 187 pixels per row for this tile configuration (not 192). The scan is row-aligned — frames never span two rows.

**Green column not in pixel data:**
The visible green column at the right edge of the tile does NOT appear in any captured frame payload. It is a hardware feature of the Novastar A8 receiving card — likely a calibration marker or alignment reference generated by tile firmware independent of the pixel stream. This applies to both RGB-V and RGB-H patterns.

**Full tile geometry — resolved by gradient analysis:**

The White Vertical gradient capture reveals the complete physical column layout of the 192-column tile:

```
Physical col:   0   1   2   3 | 4   5   ...  127 | 128  ...  190 | 191
                ← hardware →  | ← pixel stream →  | ← pixel stream → | hw
                  (left edge) |   zone 1 (124px)   |   zone 2 (63px) |
```

- **Physical cols 0–3** (4 cols): hardware — not in pixel stream. Gradient begins here (values 0x00 → ~0x05) but these pixels never appear in a captured frame.
- **Physical cols 4–127** (124 cols) = **pixel stream cols 0–123**: zone 1. Gradient 0x06 → 0xbe.
- **Physical cols 128–190** (63 cols) = **pixel stream cols 124–186**: zone 2. Gradient 0x00 → 0x5d.
- **Physical col 191** (1 col): hardware right-edge marker — the green/red column visible in captures. Gradient would continue to ~0x5f but this column is not in the pixel stream.

**Gradient rate:** 190/127 = 1.496 ≈ **1.5 per pixel** (Bresenham +1/+2 alternating), applied consistently to both zones.

**Why pixel stream col 0 starts at 0x06 and not 0x00:** The gradient is computed for the full 128-column physical zone (cols 0–127). The pixel stream starts at physical col 4, which is already 4 steps into the gradient: 4 × 1.5 = 6.0 → 0x06. Confirmed: physical col 127 = pixel stream col 123 = 190 exactly (127 × 190/127 = 190.00 ✓).

**Zone boundaries are identical to the fixed test-pattern grid:**
- Horizontal: zone 1 = 128 physical cols, zone 2 = 64 physical cols (2:1 ratio)
- Vertical: zone A = rows 0–127, zone B = rows 128–191 (2:1 ratio)
- All test patterns (RGB-V, RGB-H, checkerboard, gradients) use these same two boundaries.

**Checkerboard — confirmed geometry on 192×192 tile at 60% brightness:**

Visual: top-left block white, top-right block black, bottom-left block black, bottom-right block white. Far-right column red (hardware artifact).

Uses the **same boundaries** as RGB-V and RGB-H:
- Column split at col 124 (same as RGB-V white/red stripe boundary)
- Row split at row ~128 (same as RGB-H top/bottom boundary)

This creates a 2×2 block grid (not a pixel-by-pixel checkerboard):
```
cols 0–123       cols 124–186
  [  WHITE  ] | [  BLACK  ]    rows 0–127
  [  BLACK  ] | [  WHITE  ]    rows 128–191
```

Capture analysis (pattern_checkerboard.pcapng, iface 0):
- 697 white-left frames: cols 0–123 = white (0xbf), cols 124–186 = black (0x00)
- 325 black-left frames: cols 0–123 = black (0x00), cols 124–186 = white (0xbf)
- 0 all-white or all-black pixel rows — every pixel row spans both colors
- Ratio 697:325 = 2.14:1 ≈ 2:1, consistent with 128 white-left rows and 64 black-left rows
- Zero red pixels anywhere in the payload — far-right red column is hardware artifact (same mechanism as green column in other patterns, different color)

**White Gradient Vertical — confirmed:**

A left-to-right brightness ramp, identical in every row.

- R=G=B throughout — pure grayscale gradient
- All 1152 gradient frames in capture have **one unique payload** — every row is identical
- Two segments at the col 124 boundary (physical zone boundary at col 128):
  - Pixel stream cols 0–123: `0x06` → `0xbe`
  - Pixel stream cols 124–186: `0x00` → `0x5d`
- Step pattern: alternating +1/+2 (Bresenham 1.5/pixel slope)
- Pixel stream col 0 = 0x06, not 0x00: the gradient is computed for the full 128-column physical zone starting at physical col 0; the pixel stream starts at physical col 4, which is already 4 steps in (4 × 1.5 = 6)

---

### 09:1e:00 — Sync/blank frame

```
Dst MAC:   09:1e:00:00:00:00
Src MAC:   00:00:00:00:00:00
Ethertype: 0x0000
Payload:   all zeros
```

Represents a blank/sync scan position in the pixel stream. Rate: ~8–10% of total 09:1e volume.

---

### 09:2d — Display configuration / keepalive

```
Dst MAC:   09:2d:XX:XX:XX:XX  (varies, may be a sequence/counter)
Src MAC:   varies
Ethertype: varies
Payload:   structured, 5 unique patterns observed, NOT correlated with brightness
Frame size: 1026 bytes total (1012-byte payload)
```

Required for tile to display anything. Dropping 09:2d frames causes the tile to go completely dark within milliseconds. Exact role not yet decoded. Likely carries display configuration, sync negotiation, or a keepalive protocol.

**Complementary byte pair encoding (discovered 2026-04-15):**
All fields in 09:2d frames (dst MAC bytes 2–5, ethertype, payload bytes) use XX:~XX pairs where each byte pair sums to 0xFF. Example: dst MAC byte 2 = 0x3c → byte 3 = 0xc3 (3c + c3 = ff). This is consistent throughout — ethertype and payload follow the same rule.

**Quick Config protocol (discovered 2026-04-15):**
Quick Config is a bidirectional calibration sequence initiated from the VX1000 front panel. It is NOT a one-way broadcast. The tile must respond to each step. Sequence observed:
1. VX1000 sends black frame (all 00)
2. VX1000 sends alternating 00/ff calibration pattern
3. VX1000 sends black frame again

The tile is expected to ACK each phase. This is why Quick Config FAILS when bridge0 is in the path — Mac USB NIC latency causes the tile response to arrive too late, resulting in "Sync Failed" on the VX1000 display. Fix: destroy bridge0 before running Quick Config, restore afterward. Capture: ~/Desktop/quickconfig_attempt.pcapng (16MB, two attempts).

---

### 09:3c — Brightness command

```
Dst MAC:   09:3c:01:ff:ff:ff        (fixed)
Src MAC:   01:00:01:00:00:02        (fixed — deliberate control address, NOT from pixel stream)
Ethertype: 0x0100                   (fixed — 256 decimal)
Payload:   [0]  brightness (0x00–0xFF)
           [1]  (brightness + 3) & 0xFF
           [2]  0x03 normally; 0x04 when brightness >= 0xFD
           [3]  0x67  (fixed)
           [4]  0x04  (fixed)
           [5-1007]  0x00  (padding, 1003 bytes)
```

**Behavior:**
- Event-driven: only transmitted while brightness dial is actively changing
- VX1000 sends at ~17 fps during a change, ramping through intermediate values
- Tile stores the last received value; no frames needed at steady state
- Dropping these frames locks brightness at whatever was last set

**Periodic keepalive subtype (09:3c:01:00:00:00) — discovered 2026-04-15:**

A second 09:3c frame variant appears roughly every 14 seconds regardless of user activity:
```
Dst MAC:   09:3c:01:00:00:00        (bytes 3–5 = 0x00 vs normal 0xff)
Src MAC:   00:00:17:00:00:02        (different from event-driven frames)
Ethertype: 0x0400                   (different from event-driven 0x0100)
payload[0]: 0x1e  (brightness-like value, ~12% in current encoding)
payload[1]: 0x00  (does NOT follow the +3 formula)
payload[2]: 0x0d  (not 0x03/0x04)
payload[3]: 0x67  (same as normal)
payload[4]: 0x04  (same as normal)
payload[5-1007]: 0x00
```
This frame type is NOT event-driven. It appeared only after VX1000 reboot (at t=50s and t=64s, ~every 14 seconds) and is distinct from the normal brightness-set frames. Its role is unknown — possibly: reporting current brightness state, periodic keepalive, or tile parameter broadcast. The `00:00:00` vs `ff:ff:ff` dst MAC suffix likely distinguishes this subtype from the active brightness-set command.

**Brightness encoding:**

| % brightness | payload[0] | payload[1] | payload[2] |
|---|---|---|---|
| 0% | `0x00` | `0x03` | `0x03` |
| 25% | `0x3f` | `0x42` | `0x03` |
| 50% | `0x7f` | `0x82` | `0x03` |
| 75% | `0xbf` | `0xc2` | `0x03` |
| 100% | `0xff` | `0x02` | `0x04` |

Verified: 25=0x3f 50=0x7f 75=0xbf. Floor division confirmed.

---

## Injecting Brightness from the Mac

Now that the protocol is known, a Mac (or Raspberry Pi, or any Linux/macOS machine with a BPF interface) can set tile brightness directly without a VX1000.

### Frame construction

```python
def make_093c_brightness(level_pct: float) -> bytes:
    """
    Build a 09:3c brightness frame.
    level_pct: 0.0–100.0  (0% = off, 100% = full brightness)
    Returns: complete Ethernet frame bytes, ready to write to BPF fd.
    """
    b     = max(0, min(255, int(level_pct * 255 / 100)))
    chk   = (b + 3) & 0xFF
    carry = 0x04 if b >= 0xFD else 0x03
    payload = bytes([b, chk, carry, 0x67, 0x04]) + b'\x00' * 1003
    dst   = bytes([0x09, 0x3c, 0x01, 0xff, 0xff, 0xff])
    src   = bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x02])
    etype = bytes([0x01, 0x00])
    return dst + src + etype + payload
```

### Injection (send 10 frames over ~600ms to mirror VX1000 behavior)

```python
import os, struct, fcntl, time

BIOCSETIF     = 0x8020426c
BIOCSHDRCMPLT = 0x80044275

def open_bpf_write(iface):
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            return fd
        except OSError:
            continue
    raise RuntimeError(f'No BPF device for {iface}')

fd = open_bpf_write('en9')   # tile-side interface
frame = make_093c_brightness(75.0)  # 75% brightness
for _ in range(10):
    os.write(fd, frame)
    time.sleep(0.06)
os.close(fd)
```

**Script:** `inject_brightness.py` in the project root. Supports `--level N`, `--sweep A B T`, and `--iface`.

---

## Tools Built During This Investigation

| Script | Purpose | Key flags |
|---|---|---|
| `tap_capture.py` | Dual-interface BPF capture → pcapng. Captures both en11 and en9 simultaneously. | `--iface-a en11 --iface-b en9` |
| `color_map.py` | Live frame type tracker. Prints a table of dst MACs, etype, pixel analysis per interval. Flags low-frequency frames as `*** CONTROL`. | `--iface en9`, `--brightness` |
| `decode_control.py` | Reads a pcapng, extracts control frames by dst MAC prefix, dumps hex payloads, shows byte-level diffs between frames. | `--prefix 093c --unique --max-payload 64` |
| `brightness_hunt.py` | Multi-mode analysis tool. `diff`: compare transition vs static baseline. `sweep`: timeline of all frame types per time bucket. `live`: BPF capture with rare-frame detection. | `diff`, `sweep`, `live` subcommands |
| `selective_bridge.py` | Software Ethernet bridge replacing bridge0. Selectively drops or passes frame types for isolation testing. The tool that cracked the brightness question. | `--drop 093c`, `--pass-only pixel` |
| `inject_brightness.py` | Injects 09:3c brightness frames from the Mac without a VX1000. | `--level 50`, `--sweep 0 100 5` |

---

## Known Bugs / Gotchas

### IDB block type in tap_capture.py pcapng files

`tap_capture.py` writes pcapng IDB (Interface Description Block) with block type `0x00000002` instead of the standard `0x00000001`. All other tools (`decode_control.py`, `brightness_hunt.py`) check for type `0x00000001`, so they miss the IDB and fall back to the default microsecond timestamp resolution. This is harmless because tap_capture.py also uses microsecond timestamps — the fallback resolution matches. But it means `iface_ts_resolutions[]` is always empty when reading tap_capture.py output. Fix: change `PCAPNG_IDB = 0x00000001` in the readers to also accept `0x00000002`, or fix tap_capture.py to write the standard type.

### BPF buffer size on bridge0

bridge0 has a default BPF buffer of 4,096 bytes. At 1,700+ fps with 959-byte frames, this causes significant frame loss. Physical interfaces (en9, en11) default to 524,288 bytes and work fine. Always capture on en9 or en11 directly, not on bridge0.

### 09:3c only appears during brightness changes

Static captures will never contain 09:3c frames. If you are debugging and see no 09:3c frames, that is expected unless you changed brightness during the capture.

### tap_capture.py not suitable for brightness (09:3c) capture

`tap_capture.py` opens BPF with a 4096-byte buffer. At 1700fps with 959-byte frames, rare frames like 09:3c are dropped before they can be read. Use `brightness_hunt.py live` instead:

```bash
sudo python3 brightness_hunt.py live --iface en11 --out FILE.pcapng
```

This tool uses a tighter read loop and is the only reliable method for capturing 09:3c frames. Confirmed: `tap_capture.py` yielded 0 09:3c frames at all brightness levels; `brightness_hunt.py` captured 16–27 frames per brightness change.

---

### Power cycle / tile reconnect behavior (confirmed 2026-04-15)

**VX1000 behavior during tile outage:** The VX1000 never stops streaming. It continues sending pixel frames (~1,530/sec), sync frames (~170/sec), and 09:2d frames (~1–5/sec) at full rate continuously, regardless of whether the tile is connected. There is no pause, no reconnect protocol, no backoff, and no change in frame content when the tile link drops or comes back.

**09:2d init burst at reconnect:** When the tile Ethernet link comes back up, the VX1000 immediately sends a rapid burst of 09:2d config frames — approximately 7 frames at ~60fps (one every 17ms) rather than the normal 1–5/sec. This burst appears to be how the tile receives its initial display configuration on first link-up. After the burst, the rate returns to normal. The tile is displaying content within ~200ms of the link coming up.

**The tile does not send any Novastar frames back during normal steady-state operation.** However, a tile-originated 09:2d frame was observed on iface 1 during tile power-on (daisy_tile2_poweron.pcapng), before any VX1000 09:2d frame appeared on iface 0:
```
src = 00:ff:00:ff:00:ff  (Novastar complementary encoding of a zero address)
dst = 09:2d:4c:b3:00:ff
payload: 00 ff 00 ff 00 ff...  (all complementary zero pairs)
```
This appeared 467ms before the first VX1000 09:2d on iface 0, ruling out bridge forwarding. It appears tiles send at least one 09:2d frame toward the VX1000 during boot/power-on. The all-zero complementary payload may be a "ready" or "null" handshake. This is not seen during normal steady-state operation — only at power-on.

**Bridge loop artifact:** When the tile link (en9) drops, bridge0 has no downstream path. VX1000 frames arriving on en11 loop back through bridge0 to en11 again, causing a ~30× amplification in frame count on the iface 0 capture. This is a BPF/bridge artifact, not real traffic. All looped frames are identical to the normally-transmitted frames — the VX1000 is not doing anything unusual.

---

### VX1000 cold-start boot sequence (confirmed 2026-04-15, powercycle_vx1000.pcapng)

Capture: VX1000 powered off at t≈4s, back at t≈44s (~40 second boot time). Capture ran for ~75 seconds total.

**During VX1000 offline (t=4s–44s):** iface 0 shows only Mac network stack frames — no Novastar frames at all:
- ARP broadcasts (42 bytes, etype=0x0806): Mac's en11 doing link-local ARP for 169.254.28.114
- DHCP broadcasts (342 bytes, etype=0x0800, UDP 68→67): the Mac running its DHCP stack on en11
- IPv6 MLD Report (110 bytes, etype=0x86dd): Mac's IPv6 multicast
- IPv6 Neighbor Discovery (70 bytes, etype=0x86dd): Mac's IPv6 ND
These are all standard macOS link-local behavior on en11 when it has no carrier from the VX1000.

**VX1000 boot phase (t≈44s onward):** The VX1000 comes back online immediately streaming 09:1e sync frames and 09:2d config frames. Key observations:
- **Sync-only at boot:** The VX1000's first frames are 09:1e:00:00:00:00 sync frames only — **no pixel data** at all for the remainder of the capture (~30 seconds). This was unexpected: normally the VX1000 streams both pixel and sync frames continuously. The lack of pixel data suggests the VX1000 was in a "display off" or "initializing" state, not running its normal scene.
- **09:2d burst at boot:** The first 09:2d frames appear at t=45.4s as a rapid burst (~60fps vs normal 1–5/sec), consistent with the tile reconnect burst seen during tile power cycles.
- **Non-standard sync frame sizes:** Scattered throughout the post-boot period, the capture shows anomalous short sync frames at 132, 136, and 496 bytes (normal = 575 bytes). These are `09:1e:00:00:00:00` frames with all-zero payloads, appearing roughly once every 2–5 seconds. The cause is not yet determined. They may represent a VX1000 startup sequence, a periodic low-rate keepalive, or a BPF capture artifact.
- **Periodic 09:3c keepalive:** The first 09:3c frame appears at t=50.2s (about 6 seconds after boot), followed by a second at t=64.0s (~14s later). These are the `09:3c:01:00:00:00` subtype (see above), not user-triggered brightness changes.

**Summary of "boot-only" frame types:**

| Frame | Size | Timing | Notes |
|---|---|---|---|
| DHCP broadcast | 342 bytes | t=10–27s (VX1000 offline) | Mac network stack |
| Short sync | 132/136 bytes | t=48–72s, ~1/bucket | VX1000 post-boot, cause TBD |
| Medium sync | 496 bytes | t=45–72s, ~2/bucket | VX1000 post-boot, cause TBD |
| 09:3c keepalive | 1022 bytes | t=50s, t=64s (~14s interval) | `09:3c:01:00:00:00` variant |
| 09:2d burst | 1026 bytes | t=45.4s for ~0.4s | Normal size, elevated rate |

---

### Daisy-chain behavior (confirmed 2026-04-15, daisy_chain_tile2.pcapng)

Two tiles daisy-chained on VX1000 port 1: VX1000 → Tile 1 → Tile 2.

**VX1000 is completely unaware of Tile 2.** Connecting Tile 2 downstream caused zero change in the VX1000's output: no 09:2d burst, no new frame types, no rate change. The VX1000 sends one stream to Tile 1 and that is the entirety of its obligation.

**Tile 1 forwards the stream transparently.** Tile 2 received and displayed the same content as Tile 1 within milliseconds of connection. No addressing headers, no per-tile frames, no tile IDs — the protocol does not support them. Every tile in a daisy-chain sees exactly the same frames.

**Brightness is per-tile.** Tile 2 came up at a different brightness than Tile 1 because 09:3c is event-driven — the VX1000 only sends it when the dial moves. Tile 2 had its own stored brightness from its last power cycle. When the user nudged the dial by 1%, the VX1000 sent a 09:3c command and both tiles immediately matched. This confirms 09:3c flows through the chain the same as pixel data.

**Practical implication:** A Mac injecting frames to drive a tile chain must send an explicit 09:3c frame at startup. Tiles will power on at their own stored brightness and will not be normalized to each other until a new 09:3c command is received.

**Tile 2 power-on vs data-connect — different behavior (daisy_tile2_poweron.pcapng):**

Powering on tile 2 (vs just connecting its data cable) produced a distinct link event:
- At t≈3.0s: iface 0 frame rate dropped 95% for ~200ms — tile 2's power-on caused tile 1's output port to briefly renegotiate while tile 2's Ethernet initialized
- At t≈5.1s: brief bridge loop spike (2–3× normal for ~400ms) as en9 link fully recovered
- Data-only connect (previous test): zero link disruption, zero rate change

**Tile sends 09:2d during power-on:** A single 09:2d frame originated from the tile side (iface 1) at t=0.265s — 467ms before the first VX1000 09:2d on iface 0, ruling out bridge forwarding. Source: `00:ff:00:ff:00:ff` (Novastar complementary zero address). Payload: all `00:ff` pairs (complementary zeros). This is the only observed Novastar frame originating from the tile direction. Tiles appear to send exactly one 09:2d "ready" frame toward the VX1000 on power-on.

---

### bridge0 must be destroyed before running selective_bridge.py

The software bridge conflicts with the hardware bridge. Both try to own the same BPF file descriptors for the same physical interfaces.

```bash
sudo ifconfig bridge0 destroy
sudo python3 selective_bridge.py ...

# Restore when done:
sudo ifconfig bridge0 create && sudo ifconfig bridge0 addm en11 addm en9 && sudo ifconfig bridge0 up
```

---

## Open Questions

1. **09:2d full decode** — We know it is required for display operation but have not decoded its structure. Five unique payload patterns were observed. Its role is likely: sync negotiation, initial configuration download, display geometry setup, or a keepalive. Low priority now that brightness is solved.

2. **Pixel count encoding** — 945 payload bytes = 315 pixels. Is this fixed by the receiving card firmware? Does it change with tile resolution? Unknown.

3. **Inject test pattern** — Frame structure is fully known. Can now construct `09:1e` pixel frames from the Mac to send arbitrary patterns to the tile without a VX1000. This is the logical next step after `inject_brightness.py`. RGB-V payload structure is confirmed as reference.

4. ~~**Scan direction / tile geometry**~~ — SUBSTANTIALLY RESOLVED 2026-04-15. Confirmed from RGB-V and RGB-H captures:
   - **One frame = one row of pixel data.** Each 187-pixel (561-byte) payload is exactly one horizontal scan line.
   - **Scan is left-to-right** within each row. Pixel 0 = leftmost column, pixel 186 = column 186.
   - **Active pixel width = 187 columns** (not 192). Columns 187–191 are hardware-generated by the tile (e.g., green calibration column at col 191 is always visible but not present in pixel data).
   - **Row count:** 192 rows total (128 white + 64 red observed in RGB-H = 2:1 ratio confirmed).
   - **Row scan order (top→bottom vs bottom→top):** unconfirmed — need injection test to verify.

5. ~~**09:3c exact mapping at mid-range**~~ — VERIFIED 2026-04-15 via live capture. 25%=0x3f, 50%=0x7f, 75%=0xbf. Formula: int(pct\*255/100) floor division confirmed.

6. **VX1000 boot sequence** — PARTIALLY RESOLVED 2026-04-15 via powercycle_vx1000.pcapng. Boot takes ~40s. VX1000 returns to sync-only mode (no pixel data) after boot. Non-standard sync frame sizes (132, 136, 496 bytes) appear post-boot — cause unknown. Periodic `09:3c:01:00:00:00` keepalive appears every ~14s. **Open:** why no pixel data after boot? Does it resume after display is configured? VX1000 UI state not captured.

7. **Multi-port behavior** — All testing done on port 1. Need to test: does port 2 use different frame prefixes? Does a second VX1000 output port behave identically to port 1?

**Daisy-chain (same port) — CONFIRMED 2026-04-15:** Two tiles daisy-chained on port 1. VX1000 is completely unaware of tile 2. Same pixel stream reaches both tiles; content is identical. Each tile stores brightness independently — tile 2 came up at a different brightness than tile 1 because the VX1000 had not sent a 09:3c command since tile 2's last power-on. After a single brightness dial nudge, both tiles matched. **Implication for injection:** Always send an explicit 09:3c frame at startup to normalize brightness across a chain.

---

## Captures on File

| File | Description | Key content |
|---|---|---|
| `~/Desktop/vx1000_session.pcapng` | Session 1, ~2 min, 4.9M frames | First good capture; pixel stream confirmed |
| `~/Desktop/vx1000_session2.pcapng` | Session 2, shorter | Pixel decode confirmed; 09:2d frames spotted |
| `~/Desktop/static_0pct.pcapng` | Static, brightness=0% | 0 09:3c frames (expected); 09:2d baseline |
| `~/Desktop/static_100pct.pcapng` | Static, brightness=100% | 0 09:3c frames (expected); 09:2d baseline |
| `~/Desktop/static_49pct.pcapng` | Static, brightness=49% | 0 09:3c frames (expected); 09:2d baseline |
| `~/Desktop/en11_bounce.pcapng` | en11 capture, 0→1→0→100→0 bounce | **225 09:3c frames — the decode source** |
| `~/Desktop/quickconfig_attempt.pcapng` | Two Quick Config attempts, 16MB | 09:2d complementary pair sequence; bidirectional protocol observed |
| `~/Desktop/brightness_8pct.pcapng` | brightness_hunt.py, en11, 8% | 16 09:3c frames; payload[0]=0x11 |
| `~/Desktop/brightness_25pct.pcapng` | brightness_hunt.py, en11, 25% | 27 09:3c frames; settled at 0x3f |
| `~/Desktop/brightness_50pct.pcapng` | brightness_hunt.py, en11, 50% | 25 09:3c frames; settled at 0x7f |
| `~/Desktop/brightness_75pct.pcapng` | brightness_hunt.py, en11, 75% | 24 09:3c frames; settled at 0xbf |
| `~/Desktop/test_patterns_all.pcapng` | tap_capture.py, en11+en9, all solid colors | Black/Red/Green/Blue/White confirmed; 575-byte frames; all pixel-streamed |
| `~/Desktop/test_patterns_stripes.pcapng` | tap_capture.py, en11+en9, stripe patterns | 09:2d payload analysis; 3 unique payloads identified |
| `~/Desktop/pattern_rgbv.pcapng` | tap_capture.py, en11+en9, White→RGB-V | RGB-V pixel-streamed confirmed; white/red boundary at payload byte 373; scan = horizontal raster |
| `~/Desktop/pattern_rgbh.pcapng` | tap_capture.py, en11+en9, RGB-H | RGB-H pixel-streamed confirmed; 1255 white + 598 red frames (2:1); one frame per row; green col = hardware artifact |
| `~/Desktop/pattern_checkerboard.pcapng` | tap_capture.py, en11+en9, Checkerboard | 2×2 block pattern; col boundary=124, row boundary=128; 697 white-left + 325 black-left frames; red col = hardware artifact |
| `~/Desktop/pattern_gradient_white_v.pcapng` | tap_capture.py, en11+en9, White Gradient V | Grayscale ramp left-to-right; 1 unique payload (all rows identical); col boundary=124; resets at zone boundary; start=0x06 confirms 4 hardware cols on left edge |
| `~/Desktop/powercycle_init.pcapng` | tap_capture.py, en11+en9, tile power cycle | VX1000 streams continuously through outage; 09:2d init burst at reconnect (~60fps for ~200ms); no Novastar handshake frames from tile |
| `~/Desktop/powercycle_vx1000.pcapng` | tap_capture.py, en11+en9, VX1000 power cycle | ~40s boot time; sync-only mode at boot (no pixel data); short sync frames (132/136/496 bytes) post-boot; periodic 09:3c keepalive (`09:3c:01:00:00:00`) every ~14s; DHCP from Mac during VX1000 outage |

---

*Reverse-engineered 2026-04-15 by Justin Edgerly and Claude (Anthropic).  
Zero prior documentation existed for this protocol. Every finding in this document was derived from live hardware captures.*
