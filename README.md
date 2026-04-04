# Novastar Tile Diagnostic Tool

**A simple tool for checking LED tiles on a job site — no laptop, no NovaLCT software required.**

You tap a button on your phone. The tiles turn red, green, blue, or white. That's it.

---

## What this does

LED video walls use Novastar "receiving cards" inside each tile. When a tile looks wrong, you need to send it a test color to isolate which tile is the problem. Normally you'd need a Windows PC with Novastar's NovaLCT software installed.

This tool runs on the **Novastar T10** multimedia player you already have in the system. You connect your phone to the T10's Wi-Fi and open a web page. From there you can:

- Flash **red, green, blue, white, or a grid pattern** on all tiles at once
- Target a **single tile by number** to isolate a bad one
- Switch everything back to **normal** when you're done

No PC. No NovaLCT. Works on any phone or tablet with a browser.

---

## What you need

- A **Novastar T10** (the black box that drives your LED wall)
- Your **tiles connected via Ethernet** to the T10 as normal
- Any smartphone or tablet with a browser (iPhone, Android, iPad — anything)
- About 20 minutes to set this up once

That's it. No coding experience needed.

---

## One-time setup (do this once, takes ~20 minutes)

### Step 1 — Install Termux on the T10

Termux is a free app that lets the T10 run the web server. The T10 runs Android, so this works like installing any app.

1. On the T10 (or using a USB keyboard/mouse plugged into it), open a browser
2. Go to: **https://f-droid.org/packages/com.termux/**
3. Download and install Termux
4. Also install **Termux:Boot** from the same site (this makes the server start automatically when the T10 turns on)

> If you can't browse on the T10, download the Termux APK on your laptop, copy it to a USB drive, plug that into the T10, and install it from there.

---

### Step 2 — Copy the server files to the T10

You need to get the `server/` folder from this project onto the T10.

**Option A — USB drive:**
1. Copy the entire `novastar-diagnostic` folder to a USB drive
2. Plug the USB drive into the T10
3. Open Termux and type:
   ```
   cp -r /sdcard/novastar-diagnostic ~/novastar-diagnostic
   ```

**Option B — ADB over USB (if you're comfortable with a terminal on your laptop):**
```bash
adb push /path/to/novastar-diagnostic /sdcard/novastar-diagnostic
```
Then in Termux:
```bash
cp -r /sdcard/novastar-diagnostic ~/novastar-diagnostic
```

---

### Step 3 — Run the installer

In Termux, type these commands one at a time and press Enter after each:

```bash
cd ~/novastar-diagnostic/server
bash install.sh
```

When it asks *"Start the server now?"* — type `y` and press Enter.

The installer takes 2–5 minutes. It will say **SETUP COMPLETE** when done.

---

### Step 4 — Find your sending card's IP address

This is the IP address of the part of the T10 that talks to the tiles. You need to enter it in the app.

**How to find it:**
- Open NovaLCT on any laptop connected to the system
- Go to **User > Login**, then look at the connected sending card
- The IP shown there is what you need (usually something like `192.168.0.10`)

Write it down — you'll enter it in the app in Step 6.

---

### Step 5 — Connect your phone to the T10's Wi-Fi

1. On your phone, go to **Settings > Wi-Fi**
2. Look for a network that starts with `AP` followed by 8 digits (e.g., `AP12345678`)
   - These 8 digits are the last 8 digits of your T10's serial number
3. Connect. The default password is: **`12345678`**

---

### Step 6 — Open the tool

On your phone's browser, go to:

**http://192.168.43.1:8080**

The diagnostic tool will open. At the bottom of the screen, tap **Settings** and enter your sending card IP from Step 4. Tap **Apply & Reconnect**.

The connection indicator at the top should turn green. You're ready.

---

## Using the tool

**To test all tiles at once:**
- Make sure "ALL" is selected in the card selector
- Tap **Red**, **Green**, **Blue**, **White**, or **Grid**
- All tiles will switch to that color

**To test a single tile:**
1. Set "Cards in chain" to the number of tiles in your system and tap **Update**
2. Tap the chip for the tile you want to test (e.g., `#0`, `#1`, `#2`...)
   - Tiles are numbered starting from 0, in daisy-chain order from the first tile connected to the T10
3. Tap a color button — only that tile will change

**To return to normal:**
- Tap **NORMAL / OFF** — all tiles return to displaying the video signal

---

## Auto-start (optional — makes it work without fussing every time)

If you installed Termux:Boot in Step 1, do this once in Termux:

```bash
mkdir -p ~/.termux/boot
cat > ~/.termux/boot/start-nova-diag.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
node ~/novastar-diagnostic/server/server.js &
EOF
chmod +x ~/.termux/boot/start-nova-diag.sh
```

After this, the server starts automatically every time the T10 powers on.
You just connect your phone to the Wi-Fi and open the browser — no touching Termux.

---

## Troubleshooting

| Problem | What to check |
|---|---|
| Connection bar shows red | Sending card IP wrong — tap Settings and verify the IP |
| Buttons do nothing | Check that the Ethernet cable is connected T10 → tiles |
| Can't load the web page | Make sure your phone is connected to the T10's Wi-Fi, not your regular Wi-Fi |
| Server stopped | Open Termux and run: `bash ~/start-nova-diag.sh` |
| Wrong tile responds | Tile numbering starts at 0; #0 is the first tile connected to the T10 |
| Nothing works at all | Try switching from TCP to UDP in Settings, or vice versa |

---

## For technicians — advanced info

<details>
<summary>Protocol details, register addresses, packet structure</summary>

**Transport:** TCP port 5200 (preferred) or UDP port 5201

**Test pattern register:** `0x02000101` (SelfTestMode, 1 byte write)

| Mode  | Value | Register |
|-------|-------|----------|
| Off   | 0     | 0x02000101 |
| Red   | 2     | 0x02000101 |
| Green | 3     | 0x02000101 |
| Blue  | 4     | 0x02000101 |
| White | 5     | 0x02000101 |
| Grid  | 6     | 0x02000101 |

**Packet structure** (all multi-byte values little-endian):

```
[0-1]   55 AA       — Request header
[2]     00          — Status (0 = success)
[3]     NN          — Serial number (increments per packet)
[4]     FE          — Source: Computer
[5]     FF/00       — Destination: FF = broadcast, 00 = specific card
[6]     01          — Device type: Receiving card
[7]     FF/00       — Port: FF = all
[8-9]   FF FF / NN  — Card index uint16 LE: FFFF = all, or card number
[10]    01          — I/O direction: Write
[11]    00          — Padding
[12-15] NN NN NN NN — Register address uint32 LE
[16-17] NN 00       — Data length uint16 LE
[18+]   NN          — Data bytes
[-2,-1] NN NN       — Checksum uint16 LE = (sum(bytes[2..end]) + 0x5555) & 0xFFFF
```

**Verified against brightness example packet:**
`55 AA 00 00 FE FF 01 FF FF FF 01 00 01 00 00 02 01 00 00 55 5A`
content sum = 0x0500, + 0x5555 = 0x5A55 → bytes `55 5A` ✓

**Protocol source:** Reverse-engineered from NovaLCT traffic.
Reference: [sarakusha/novastar](https://github.com/sarakusha/novastar)

**Packet analyzer:** Run `python3 analyzer/parse_capture.py your_capture.pcapng` to decode a Wireshark capture and verify register values against your specific firmware.

</details>

---

## Files in this repo

```
novastar-diagnostic/
├── analyzer/
│   └── parse_capture.py    ← Wireshark .pcapng analyzer (Python, run on your laptop)
├── server/
│   ├── server.js            ← Web server (runs on T10 in Termux)
│   ├── package.json         ← Node.js dependencies
│   ├── install.sh           ← Automated setup script for Termux
│   └── public/
│       └── index.html       ← The web UI you open on your phone
└── README.md                ← This file
```

---

*Built for professional AV/broadcast/film LED work. Tested on Novastar T10 Taurus.*
*Protocol reference: [sarakusha/novastar](https://github.com/sarakusha/novastar)*
