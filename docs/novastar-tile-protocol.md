# Novastar Tile Protocol — Plain Language Reference

**Author:** Justin Edgerly with Claude (Anthropic)  
**Date:** 2026-04-15  
**Based on:** Live hardware captures from VX1000 → Novastar A8 tile inline session

---

## The Big Picture

The Novastar VX1000 sends pixel data to an LED tile over a standard Ethernet cable. There is no Wi-Fi, no TCP/IP, no web protocol, no management layer — it is raw bytes over Ethernet, at about 1,700 frames per second, continuously, as long as the VX1000 is powered on.

We captured this traffic by placing a Mac inline between the VX1000 and the tile (VX1000 → Mac USB NIC en11 → macOS bridge → Mac USB NIC en9 → tile). The bridge passes every frame transparently — the tile has no idea the Mac is there. We used raw BPF socket captures on both interfaces simultaneously, which let us see exactly what the VX1000 sends and what the tile receives.

Everything in this document was derived from those captures. There is no public documentation for this protocol. Zero prior knowledge existed.

---

## What Is NOT Happening

Before describing what it is, it helps to clear up what it isn't:

- It is **not** a standard video signal (HDMI, DisplayPort, SDI)
- It is **not** using IP or TCP/UDP
- It is **not** using standard Ethernet addressing (the MAC addresses are fake)
- It is **not** using a Novastar management protocol (the T10 `55 AA` protocol runs on a separate management port)
- The **brightness** is not encoded in the pixel brightness values — pixels are always sent at full intensity, and brightness is a separate command

---

## Frame Types on the Wire

Four distinct frame types appear in every capture. Each is identified by its first two bytes:

| First 2 bytes | Name | Rate | Purpose |
|---|---|---|---|
| `09 1e` | Pixel data | ~1,530 / sec | Carries the actual RGB image |
| `09 1e` + all-zero rest | Sync/blank | ~170 / sec | Timing signal between scan lines |
| `09 2d` | Display config | 1–5 / sec | Required for display operation (structure unknown) |
| `09 3c` | Brightness | ~17 / sec (only during changes) | Sets LED brightness |

Total throughput: roughly **1,700 frames per second**, sustained continuously. That's a new Ethernet frame arriving every 0.6 milliseconds.

---

## The Pixel Frame — What It Actually Is

This is the core insight of the whole protocol.

Ethernet frames have a standard structure: 6 bytes destination MAC, 6 bytes source MAC, 2 bytes ethertype, then payload. Novastar ignores this structure entirely. The "Ethernet frame" they send is actually a raw pixel stream with a 2-byte prefix.

**The actual layout:**

```
Byte 0:   09            ← Novastar magic byte 1 (constant)
Byte 1:   1e            ← Novastar magic byte 2 (identifies pixel frame type)
Byte 2:   R             ← Red channel of pixel 0
Byte 3:   G             ← Green channel of pixel 0
Byte 4:   B             ← Blue channel of pixel 0
Byte 5:   R             ← Red channel of pixel 1
Byte 6:   G             ← Green channel of pixel 1
Byte 7:   B             ← Blue channel of pixel 1
Byte 8:   R             ← Red channel of pixel 2
...and so on for 187 pixels total...
Byte 562: B             ← Blue channel of pixel 186 (last pixel)
```

The Ethernet switch — and macOS bridge — see bytes 0–5 as a "destination MAC address" and bytes 6–11 as a "source MAC address" and bytes 12–13 as an "ethertype." They forward the frame normally because it looks valid. But those fields mean nothing from Novastar's perspective. Everything from byte 2 onward is just pixels.

**Total frame size: 575 bytes** (2-byte prefix + 12 bytes of "fake header" + 561 bytes of payload = 187 pixels × 3 bytes each).

---

## Pixel Encoding

Each pixel is 3 bytes: Red, Green, Blue, in that order. Each channel is 8 bits (0–255).

- `0x00` = that channel is fully off
- `0xFF` = that channel is fully on

**Why does white look like `0xBF` instead of `0xFF`?**

When the VX1000 is set to 60% brightness, it sends white pixels as `R=0xBF, G=0xBF, B=0xBF`. At 100% brightness, white pixels would be `R=0xFF, G=0xFF, B=0xFF`. The pixel VALUES sent by the VX1000 represent the full desired color at the current brightness level — the VX1000 bakes the brightness into the pixel values rather than relying on the tile to scale them.

Wait — actually that's not quite right. We verified that the pixel values are identical at 0%, 49%, and 100% brightness (the VX1000 always sends `0xBF` for white regardless of brightness setting). Brightness is handled separately by the tile via the `09:3c` brightness command frames. The `0xBF` appears to be the VX1000's internal "full white" value at its default output level, not a brightness-scaled value. Why `0xBF` and not `0xFF` is still unclear — it may be related to the tile's PWM range or a firmware-defined "100% output" level.

**Confirmed pixel values at 60% brightness setting:**

| Color | Red | Green | Blue |
|---|---|---|---|
| Black | `0x00` | `0x00` | `0x00` |
| White | `0xBF` | `0xBF` | `0xBF` |
| Red | `0xBF` | `0x00` | `0x00` |
| Green | `0x00` | `0xBF` | `0x00` |
| Blue | `0x00` | `0x00` | `0xBF` |

---

## How the Display Is Scanned — One Frame Per Row

This was the most important geometry finding.

The 192×192 tile is scanned **row by row, left to right**. Each Ethernet pixel frame carries exactly **one complete row** of pixel data: 187 pixels = 561 bytes.

So the VX1000 sends:
- Frame 1: pixels for row 0 (top row), columns 0–186, left to right
- Frame 2: pixels for row 1, columns 0–186, left to right
- Frame 3: pixels for row 2...
- ...
- Frame 192: pixels for row 191 (bottom row, assuming top-to-bottom order)
- Then it starts over

One complete refresh of the display = **192 consecutive pixel frames**. At 1,530 pixel frames per second, the tile refreshes at approximately **8 frames per second**. (1,530 ÷ 192 = ~8 Hz display refresh rate.)

**There is no explicit frame-start or frame-end marker.** There is no header saying "this is the beginning of row 47." The tile presumably tracks position implicitly — it counts pixels from the last sync event, or relies on the frame sequence, or uses some aspect of the `09:2d` config frame to establish timing. We haven't determined the exact mechanism.

**How we confirmed one-frame-per-row:**

For the RGB-H test pattern (solid white top half, solid red bottom half), every single pixel frame is either entirely white or entirely red — never mixed. If the scan were continuous across row boundaries, some frames would necessarily contain white pixels at the start and red pixels at the end (at the transition row). The complete absence of any such mixed frame proves the frames are row-aligned.

---

## The Active Pixel Area: 187 Columns, Not 192

The tile physically has 192×192 pixels. But the VX1000 only sends **187 pixels per row** in the pixel stream.

The visible tile display shows 187 pixel columns of streamed content, then a single-pixel-wide column on the far right edge whose color varies by pattern type. This column is **not present in any captured frame payload** — it never appears in the pixel data stream. It is generated directly by the tile hardware.

Across all captures:
- RGB-V test pattern: far-right column appears **green**
- RGB-H test pattern: far-right column appears **green**
- Checkerboard test pattern: far-right column appears **red**

This column changes color depending on the active pattern — we don't know the rule. It may be a calibration indicator, status LED behavior, or a tile firmware marker. But it is definitively not part of the pixel stream in any pattern we've captured.

Columns 187–191 (5 columns wide) at the right edge of the display appear to be hardware-controlled, not pixel-stream-controlled.

**So the effective layout is:**
- Columns 0–186: pixel-streamed (controlled by the VX1000)
- Columns 187–191: tile hardware (color marker column + possibly unused columns)

---

## What the "Destination MAC" Actually Tells You

Since the dst MAC bytes 2–5 are just the first 4 bytes of the pixel stream, they implicitly reveal what the first pixel of that frame looks like:

- `bf:bf:bf:bf` → frame starts with a white pixel
- `bf:00:00:bf` → frame starts with a red pixel (R=0xBF, G=0x00, B=0x00, then next pixel's R=0xBF)
- `00:00:00:00` → frame starts with a black/zero pixel (this includes both sync frames and any row that starts with black pixels)

This turns out to be a useful shortcut. When doing live captures you can immediately tell what region a frame is scanning just by looking at the dst MAC, without parsing the payload.

---

## Sync / Blank Frames

About 10% of all `09:1e` frames have an all-zero payload and all-zero "MAC addresses." These are sync or blank frames.

```
Byte 0-1:  09 1e
Bytes 2+:  00 00 00 00 00 00 ... (all zero, 573 bytes total)
```

They appear at ~170 per second, continuously, regardless of what test pattern or content is being displayed. Their exact role is unclear. Possibilities:

- Timing pulses that the tile uses to synchronize its internal scan
- Blank scan lines representing rows between visible content
- An artifact of how the VX1000 times its output at the start/end of each display frame

The fact that they appear continuously even during active white or red patterns (where there are no "black" pixels in the content) suggests they are distinct from content frames rather than just black-pixel rows.

---

## The Display Config Frame (09:2d)

Every capture contains a slow stream of `09:2d` frames — about 1 to 5 per second.

We know two things about them with certainty:

**1. They are required.** If you drop all `09:2d` frames using a software bridge filter, the tile goes completely dark within milliseconds. It does not recover until `09:2d` frames resume. The pixel data can be flowing perfectly and the tile will display nothing without these frames.

**2. They use "complementary byte pair" encoding.** Every two adjacent bytes in the `09:2d` frame (destination MAC, source MAC, ethertype, and payload) sum to exactly `0xFF`. If one byte is `0x3C`, the next is `0xC3`. If one is `0xB8`, the next is `0x47`. This is consistent throughout the entire frame without exception.

Beyond that, we do not know what these frames are doing. Five unique payload patterns were observed cycling continuously. The pattern does not change with brightness, test pattern selection, or any other variable we've tested. It may be a keepalive heartbeat, a display geometry configuration, or a synchronization protocol. Its structure has not been decoded.

---

## The Brightness Command (09:3c)

Brightness is controlled entirely separately from the pixel stream.

```
Bytes 0-1:   09 3c           ← Brightness frame magic bytes
Bytes 2-5:   01 ff ff ff     ← Fixed "MAC" bytes (not pixel data)
Bytes 6-11:  01 00 01 00 00 02  ← Fixed source (deliberate control address)
Bytes 12-13: 01 00           ← Fixed ethertype
Byte 14:     brightness      ← The actual brightness value (0x00 to 0xFF)
Byte 15:     brightness + 3  ← Checksum/carry byte
Byte 16:     0x03 or 0x04    ← Carry flag (0x04 if byte 14 >= 0xFD, else 0x03)
Byte 17:     0x67            ← Fixed
Byte 18:     0x04            ← Fixed
Bytes 19+:   0x00 × 1003     ← Zero padding
```

**Brightness value encoding:**

The brightness percentage maps to a 0–255 byte value using floor division:

```
byte = int(percentage × 255 / 100)
```

| Percentage | Hex value |
|---|---|
| 0% | `0x00` |
| 8% | `0x11` |
| 25% | `0x3F` |
| 50% | `0x7F` |
| 75% | `0xBF` |
| 100% | `0xFF` |

**Important behaviors:**

- These frames are **only sent while the brightness dial is actively moving** (~17 frames per second during a change)
- When the dial stops, no more brightness frames are sent
- The tile remembers the last brightness value it received and holds it indefinitely
- If you power cycle the tile, it presumably returns to a default brightness until it receives a new `09:3c` frame

We have verified injection works: a Mac can send these frames directly to the tile (bypassing the VX1000) and change the brightness immediately.

**Periodic keepalive variant:**

A second, distinct `09:3c` frame type was discovered during the VX1000 cold-start capture. It uses different header bytes:

```
Bytes 0-5:  09 3c 01 00 00 00   ← Note: bytes 3-5 are 0x00, not 0xff
Bytes 6-11: 00 00 17 00 00 02   ← Different source address
Bytes 12-13: 04 00              ← Different ethertype
```

This frame appears roughly every 14 seconds regardless of any user action — it is NOT triggered by brightness dial movement. It appeared after VX1000 reboot even with no user interaction. Its role is unknown — possibly a periodic status broadcast, a keepalive, or a "current brightness" report. It is distinct from the event-driven brightness-set command and should not be confused with it.

---

## How the VX1000 Drives Test Patterns

There is no "set test pattern" command frame. The VX1000 does not tell the tile "display a checkerboard now." Instead, it just sends the checkerboard pixel values as the pixel stream.

**Checkerboard — confirmed:**

The VX1000 checkerboard is not a pixel-by-pixel alternating pattern. It is a **2×2 large block pattern** that uses the exact same column and row boundaries as RGB-V and RGB-H:

```
Columns 0–123    Columns 124–186
  [ WHITE ]    |   [ BLACK ]      Rows 0–127
  [ BLACK ]    |   [ WHITE ]      Rows 128–191
```

Every single pixel row in the capture contains both white and black pixels — there are no all-white or all-black rows. The split in each row is always at column 124, and the top 2/3 of rows have white on the left while the bottom 1/3 have black on the left.

This reveals something important: **the VX1000 uses a fixed internal grid for all multi-color test patterns.** RGB-V, RGB-H, and checkerboard all divide the display at the same two lines — column 124 and row ~128. The patterns only differ in which color gets assigned to each resulting quadrant. This is almost certainly a fixed aspect of the VX1000 firmware or the tile's configured scan geometry.

**White Gradient Vertical — confirmed, and the most revealing capture yet:**

The White Vertical gradient is a left-to-right brightness ramp. Every row in the pixel stream has an identical payload — the same values column by column, repeated for all 192 rows. "Vertical" in Novastar's terminology means the gradient runs along vertical stripes (left to right), with constant brightness top to bottom in each column.

The gradient divides at the same col 124 boundary as everything else. Segment 1 (cols 0–123) ramps from brightness 0x06 to 0xbe. Segment 2 (cols 124–186) ramps from 0x00 to 0x5d. Both use the same 1.5/column rate.

**Why does segment 1 start at 0x06 instead of 0x00?**

This question cracked open the full tile geometry. The gradient is computed for the full 128-column physical zone of the tile, starting at physical col 0 = value 0. But the pixel stream doesn't start at physical col 0 — it starts 4 columns in. Physical col 4 = pixel stream col 0, and 4 × 1.5 = 6. The gradient had already ramped to 6 before the pixel stream begins. Physical col 127 = pixel stream col 123 = value 190 exactly (127 × 190/127 = 190.00). The math is exact.

**Complete tile geometry, confirmed:**

```
Physical columns:   0   1   2   3 | 4  5  ...  127 | 128  ...  190 | 191
                    ← HW (left) → | ← pixel zone 1 → | ← pixel zone 2 → | HW
                     (4 columns)  |   (124 columns)  |   (63 columns)  |  1
                                  Total pixel stream: 187 columns
                                  Total physical: 4 + 124 + 63 + 1 = 192 ✓
```

- Physical cols 0–3: hardware left edge — not in pixel stream; the gradient starts here but we never see these values in the data
- Physical cols 4–127 = pixel stream cols 0–123: zone 1 (124 columns)
- Physical cols 128–190 = pixel stream cols 124–186: zone 2 (63 columns)
- Physical col 191: hardware right-edge marker — the green/red status column

The zone widths in physical pixels are 128 and 64 — exactly 2:1, matching the row split (rows 0–127 and rows 128–191). The VX1000's internal grid divides the full physical tile 2:1 in both dimensions.

Every test pattern — solid colors, vertical stripes, horizontal stripes, checkerboard — is generated inside the VX1000 and streamed row by row as raw RGB data. The tile only receives pixels. It has no knowledge of what "test pattern" mode the VX1000 is in. This means:

- A Mac could display any pattern on the tile by constructing and sending the correct pixel frames
- The tile does not need to implement any pattern generation — it's all in the sender
- Switching patterns on the VX1000 takes effect immediately (within one display refresh, ~125ms)

---

## What Determines Which Row a Frame Goes To

This is partially answered and partially open.

**What we know:** The VX1000 sends rows in order, as a continuous stream. Row 0 first (presumably top), then row 1, then row 2, and so on to row 191, then back to row 0. There is no row number inside the frame itself.

**How the tile knows which row it's receiving:** Unknown. The tile must maintain position state internally. It likely resets its row counter at some sync boundary — either the `09:2d` config frames establish this, or there is a specific sync frame pattern we haven't decoded yet, or the tile simply counts received pixel frames from a known reset point. We have not identified a definitive "start of frame" (meaning start of a complete 192-row refresh cycle) signal in the captures.

**What we confirmed:** Row scanning is horizontal (left to right across columns) and frame-aligned (each frame = exactly one row). We have not confirmed whether rows are sent top-to-bottom or bottom-to-top — this would require injecting a test pattern and observing which end of the tile it appears on.

---

## Frame Rate and Refresh Rate

| Quantity | Value | Notes |
|---|---|---|
| Total frames/sec | ~1,700 | All frame types combined |
| Pixel frames/sec | ~1,530 | `09:1e` non-zero frames |
| Sync frames/sec | ~170 | `09:1e` all-zero frames |
| Config frames/sec | 1–5 | `09:2d` frames |
| Brightness frames/sec | 0 (static) or ~17 (changing) | `09:3c` frames |
| Pixel frame size | 575 bytes | 187 pixels × 3 bytes + 14-byte header |
| Pixels per frame | 187 | One complete row |
| Rows per display | 192 | Full tile height |
| **Display refresh rate** | **~8 Hz** | 1,530 pixel frames ÷ 192 rows |

The ~8 Hz display refresh rate is low for a video panel but fine for the static patterns and diagnostic use cases this tool targets. A production video wall would require a faster protocol or a different tile configuration — there may be a higher-rate scan mode we haven't encountered.

---

## Injecting From the Mac (What Works Today)

We have confirmed that a Mac with a BPF-capable interface (any macOS machine with an Ethernet port) can:

- **Set tile brightness** to any value without a VX1000 (inject `09:3c` frames)
- **Construct the frame structure** for arbitrary pixel data — the `09:1e` format is fully known

The `inject_brightness.py` script in this project does the brightness injection. A pixel injection script (`inject_pattern.py`) has not been written yet but the format is fully known from the captures.

One caveat: the tile also requires `09:2d` frames to display anything. We can construct pixel frames and brightness frames, but we cannot yet construct valid `09:2d` frames because we haven't decoded their structure. A Mac sending only pixel frames without `09:2d` frames would likely produce a dark tile. The `09:2d` decode is the last remaining blocker for a fully VX1000-independent tile controller.

---

## Open Questions

These are the things we do not yet know, in rough order of importance:

**1. What do the 09:2d frames actually contain?**

We know they're required and that they use complementary byte pair encoding, but we don't know what they're configuring. Five unique payload patterns cycle continuously. Are they setting the tile's display geometry? Establishing a sync protocol? Sending a keepalive heartbeat? Until this is decoded, we cannot drive a tile independently from a Mac — we'd need to replay captured `09:2d` frames, which may or may not be sufficient.

**2. Is there a "start of frame" signal?**

A complete display refresh is 192 rows. Is there any signal in the stream that marks "row 0 is next"? If yes, what is it — a specific sync frame pattern, a specific `09:2d` payload, something in the ethertype field? If no, how does the tile know where it is in the refresh cycle after power-on or reconnect? We have not identified this mechanism.

**3. Are rows scanned top-to-bottom or bottom-to-top?**

We know the scan goes left-to-right within each row, and that each frame is one row. We do not know whether row 0 appears at the top or the bottom of the physical display. A simple test — inject a pattern with a single white row at "row 0" and observe which physical row lights up — would answer this immediately.

**4. Why 0xBF for "full white" and not 0xFF?**

The VX1000 consistently sends `0xBF` as the peak pixel value in test patterns (at 60% brightness). We confirmed the pixel values do not change with brightness (the tile handles brightness via `09:3c`). So why `0xBF`? Is this a firmware constant? Is it related to the tile's PWM headroom? Is there a mode where the VX1000 sends `0xFF`? Unknown.

**5. What are columns 187–191 on the tile?**

The tile is physically 192 columns wide, but only 187 columns are driven by the pixel stream. The rightmost 5 columns (187–191) appear to be under tile hardware control. Column 191 is always green during test patterns — is this a dedicated status/calibration LED? Can these columns be controlled via `09:2d` or some other frame? Do other Novastar tile models have a different number of hardware-controlled columns?

**6. ~~What happens at power-on?~~ — SUBSTANTIALLY ANSWERED**

We captured both a tile power cycle and a VX1000 power cycle.

**Tile power cycle:** The VX1000 never stops streaming. It continued sending pixel frames, sync frames, and 09:2d config frames at full rate throughout the 5-second tile outage. When the tile link came back up, the VX1000 immediately sent a burst of ~7 rapid-fire 09:2d config frames (every 17ms, vs the normal ~250ms spacing). The tile was displaying content within 200ms of the link restoring. The tile sends no Novastar frames back — it is a purely passive receiver.

**VX1000 cold start (~40 second boot time):** After the VX1000 came back online, it immediately began sending sync frames (`09:1e:00:00:00:00`) and 09:2d config frames — but **no pixel data at all** for the full duration of our capture (~30 seconds post-boot). The VX1000 appeared to be in a "display off / initializing" state, not running its normal scene.

Additional observations during/after VX1000 boot:
- Sporadic short sync frames appear: 132-byte and 136-byte frames (normal = 575 bytes), roughly one per few seconds. Cause unknown.
- Medium sync frames at 496 bytes also appear. Cause unknown.
- A periodic `09:3c:01:00:00:00` frame (different from the normal event-driven `09:3c:01:ff:ff:ff`) appears every ~14 seconds. This appears to be a brightness keepalive or status broadcast — not triggered by user action.

**Open sub-question:** Why does the VX1000 send no pixel data after boot? Does it wait for Quick Config to complete, or for a UI interaction, before resuming the pixel stream? We stopped the capture before observing a return to normal pixel streaming.

**7. Does the display refresh rate change?**

We observe ~8 Hz at our current configuration. Is this fixed, or can the VX1000 be configured for higher rates? Are there `09:2d` payloads that alter the scan configuration? A different scan config was observed in earlier captures (959-byte frames instead of 575-byte frames), suggesting the VX1000 can operate in different modes.

**8. What is the brightness value encoding at 100% vs what the tile can receive?**

The `09:3c` payload byte ranges from `0x00` to `0xFF`. We've verified values up to `0xFF` (100%). Is the tile capable of going above 100% — is there a way to overdrive brightness beyond the VX1000 dial maximum? Unknown.

**9. Multi-tile / multi-port behavior**

**Daisy-chain on the same port — ANSWERED (2026-04-15):** We connected a second tile daisy-chained through Tile 1. The VX1000 was completely unaware — no new commands, no burst, no change of any kind in the stream. Tile 1 forwards the stream transparently. Tile 2 displayed the same content as Tile 1 immediately. The protocol has no tile addressing; every tile in the chain sees the same frames.

Brightness is stored independently per tile. Tile 2 came up at its own saved brightness. One brightness dial nudge sent a 09:3c command and both tiles matched. For NovaTool: always inject a 09:3c frame at startup to normalize the whole chain.

**Still open:** Does VX1000 port 2 use different frame prefixes than port 1?

**10. Can we replay 09:2d frames from a capture to drive the tile independently?**

The most practical near-term question: if we replay the `09:2d` frames from a known-good capture alongside our own pixel frames, will the tile display our content? Or do the `09:2d` frames need to be "live" (containing a sequence counter that the tile validates)? The complementary byte pair encoding suggests the payload content matters, but whether the exact values matter or just the structure is unknown.

---

*This document reflects everything confirmed as of 2026-04-15 from live hardware captures. All findings are based on observed data — no Novastar documentation was used or available.*
