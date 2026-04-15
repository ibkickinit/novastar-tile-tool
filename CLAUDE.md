# Novastar VX1000 Protocol — Project Context for Claude

This file is read automatically at session start. It reflects the current state of the reverse-engineering effort and all code in this repo. Read this before doing anything.

**Last updated:** 2026-04-15 (Session 2 complete)  
**Full protocol reference:** `docs/vx1000-protocol-complete.md`

---

## What This Project Is

Reverse-engineering the Novastar VX1000 LED processor data port protocol. Goal: build a Mac tool that can control LED tiles (brightness, test patterns, pixel injection) without a VX1000.

Hardware is inline — the Mac sits between the VX1000 and the tile:

```
VX1000 data port 1
        │
       en11  (Mac USB NIC, MAC c8:a3:62:b0:24:72)  ← VX1000 side
        │
    [ bridge0 ]  ← macOS Layer 2 bridge, no IP
        │
       en9   (Mac USB NIC, MAC 4c:ea:41:64:67:d8)  ← tile side
        │
LED tile (Novastar A8 receiving card)
```

---

## Protocol Status — COMPLETE (as of 2026-04-15)

All four frame types are decoded. Brightness is fully verified.

| Frame type | Dst MAC | Rate | Status |
|---|---|---|---|
| Pixel data | `09:1e:RR:GG:BB:RR` | ~1,530/sec | ✅ Fully decoded |
| Sync/blank | `09:1e:00:00:00:00` | ~170/sec | ✅ Fully decoded |
| Display config | `09:2d:XX:XX:XX:XX` | 1–5/sec | ⚠️ Role confirmed (required), structure TBD |
| Brightness | `09:3c:01:ff:ff:ff` | ~17/sec during changes | ✅ Fully decoded + verified |

### Brightness encoding (09:3c) — VERIFIED

```
payload[0] = int(pct * 255 / 100)   ← floor division, NOT round()
payload[1] = (payload[0] + 3) & 0xFF
payload[2] = 0x04 if payload[0] >= 0xFD else 0x03
payload[3] = 0x67  (fixed)
payload[4] = 0x04  (fixed)
payload[5:] = 0x00 * 1003  (padding)
```

Verified values: 8%=0x11, 25%=0x3f, 50%=0x7f, 75%=0xbf  
Frame is event-driven — only sent while dial is actively moving. Tile holds last value.

### 09:2d — Complementary byte pair encoding

All fields (dst MAC bytes 2–5, ethertype, payload) use XX:~XX pairs summing to 0xFF.  
Example: byte=0x3c → next byte=0xc3 (0x3c + 0xc3 = 0xff).

### Quick Config — FAILS with bridge0 in path

Quick Config is bidirectional. The tile must ACK each phase. Mac USB NIC latency causes tile response to arrive too late → "Sync Failed" on VX1000 display.  
**Fix: `sudo ifconfig bridge0 destroy` before running Quick Config, restore afterward.**

---

## Scripts

| Script | Purpose | Notes |
|---|---|---|
| `tap_capture.py` | Dual-iface BPF capture → pcapng | Use for pixel/pattern captures. 1MB BPF buffer (fixed). |
| `brightness_hunt.py` | Live 09:3c capture + analysis | **Only reliable tool for 09:3c frames.** tap_capture.py drops them. |
| `decode_control.py` | Decode pcapng control frames | `--prefix 093c --unique`, `--iface 0` (VX1000) or `--iface 1` (tile) |
| `color_map.py` | Live frame type tracker | Flags low-freq frames as `*** CONTROL` |
| `selective_bridge.py` | Software bridge with frame filtering | Requires `bridge0 destroy` first |
| `inject_brightness.py` | Inject 09:3c frames (no VX1000 needed) | `--level 50`, `--sweep 0 100 5` |

### Key commands

```bash
# Bridge setup
sudo ifconfig bridge0 create && sudo ifconfig bridge0 addm en11 addm en9 && sudo ifconfig bridge0 up

# Brightness capture (ONLY reliable method for 09:3c)
sudo python3 brightness_hunt.py live --iface en11 --out ~/Desktop/FILENAME.pcapng

# Pixel/pattern capture
sudo python3 tap_capture.py --mgmt-iface en11 --tile-iface en9 --out ~/Desktop/FILENAME.pcapng

# Decode 09:3c from a capture
sudo python3 decode_control.py --prefix 093c --unique ~/Desktop/FILENAME.pcapng

# Decode by interface (0=VX1000 side, 1=tile side)
sudo python3 decode_control.py --prefix 092d --iface 0 ~/Desktop/FILENAME.pcapng

# Inject brightness (no VX1000 needed)
sudo python3 inject_brightness.py --level 75

# Remove bridge before Quick Config
sudo ifconfig bridge0 destroy
```

---

## Known Bugs / Gotchas

1. **tap_capture.py cannot capture 09:3c frames** — BPF buffer was 4096 bytes; now 1MB (fixed). Even with 1MB, use `brightness_hunt.py live` for brightness work — it has a tighter read loop.

2. **BPF buffer on bridge0 is 4096 bytes** — Always capture on `en9` or `en11` directly, never on `bridge0`.

3. **09:3c only appears during brightness changes** — Static captures will always show 0 09:3c frames. This is expected.

4. **bridge0 + selective_bridge.py conflict** — Destroy `bridge0` before running `selective_bridge.py`.

5. **IDB block type in tap_capture.py pcapng** — Writes type `0x00000002` instead of `0x00000001`. Readers fall back to default microsecond timestamps. Harmless but non-standard.

---

## Open Questions (as of Session 2)

1. **09:2d full decode** — Structure unknown. 5 unique payload patterns. Role: sync/config/keepalive (TBD).
2. **Pixel count encoding** — 945 bytes = 315 RGB pixels. Fixed by firmware or tile resolution?
3. **Inject test pattern** — 09:1e structure fully known. Ready to build `inject_pattern.py`.
4. **Scan direction / tile geometry** — Unknown scan order (raster? serpentine? column?).
5. **Multi-port / multi-tile** — Only tested: single tile on port 1.

---

## Pending Captures (not yet run)

All require bridge0 up (en11 + en9). Use `tap_capture.py` for pixel/pattern; `brightness_hunt.py` for brightness.

```bash
# 1. All test patterns
sudo python3 tap_capture.py --mgmt-iface en11 --tile-iface en9 \
  --out ~/Desktop/test_patterns_all.pcapng
# During: cycle Black → Red → Green → Blue → White → RGB Vertical → RGB Horizontal → Checkerboard, ~5s each

# 2. Blackout test
sudo python3 tap_capture.py --mgmt-iface en11 --tile-iface en9 \
  --out ~/Desktop/blackout_test.pcapng
# During: hold Black → switch to White → back to Black

# 3. Brightness sweep slow
sudo python3 brightness_hunt.py live --iface en11 \
  --out ~/Desktop/brightness_sweep_slow.pcapng
# During: slowly sweep 0→100→0 on VX1000 dial

# 4. Power cycle init sequence
sudo python3 tap_capture.py --mgmt-iface en11 --tile-iface en9 \
  --out ~/Desktop/powercycle_init.pcapng
# During: power cycle the VX1000
```

---

## Captures on File (~/Desktop)

| File | Key content |
|---|---|
| `vx1000_session.pcapng` | Session 1, 4.9M frames — pixel stream confirmed |
| `vx1000_session2.pcapng` | Session 2 — 09:2d frames spotted |
| `static_0pct.pcapng` | 0% brightness static baseline |
| `static_100pct.pcapng` | 100% brightness static baseline |
| `static_49pct.pcapng` | 49% brightness static baseline |
| `en11_bounce.pcapng` | **225 09:3c frames — the decode source** |
| `quickconfig_attempt.pcapng` | Two Quick Config attempts — 09:2d bidirectional protocol |
| `brightness_8pct.pcapng` | 16 09:3c frames; payload[0]=0x11 |
| `brightness_25pct.pcapng` | 27 09:3c frames; settled at 0x3f |
| `brightness_50pct.pcapng` | 25 09:3c frames; settled at 0x7f |
| `brightness_75pct.pcapng` | 24 09:3c frames; settled at 0xbf |

---

## Repos

| Repo | Purpose |
|---|---|
| `ibkickinit/novastar-tile-tool` | This repo — all capture/analysis scripts + docs |
| `ibkickinit/novastar-demo` | NovaTool UI demo (index.html) — no changes this session |
| `ibkickinit/Claude` | Cross-session memory mirror — `novastar/` folder has all scripts + docs |

PAT is in memory file `reference_github.md`.
