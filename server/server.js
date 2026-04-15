#!/usr/bin/env node
/**
 * Novastar LED Tile Diagnostic Server
 * Runs on Pi4 CM (production) or T10 via Termux (dev).
 * Serves web UI, provides REST API for processor state,
 * and sends protocol commands to Novastar sending/receiving cards.
 *
 * Usage:  node server.js [--debug]
 * Config: ./config/novatool.config.json (falls back to env vars / defaults)
 */

"use strict";

const express = require("express");
const fs      = require("fs");
const net     = require("net");
const dgram   = require("dgram");
const path    = require("path");

// ─── Configuration ────────────────────────────────────────────────────────────
// Load from config file if it exists, fall back to env vars / defaults

const CONFIG_PATH = path.join(__dirname, "config", "novatool.config.json");
let siteConfig = {};
try {
  siteConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));
  console.log(`[CFG] Loaded config from ${CONFIG_PATH}`);
} catch (e) {
  console.log(`[CFG] No config file found at ${CONFIG_PATH}, using defaults`);
}

const netCfg = siteConfig.network || {};

const CONFIG = {
  SENDING_CARD_IP:   process.env.NOVA_IP   || netCfg.sending_card_ip || "192.168.0.10",
  PROTOCOL:          process.env.NOVA_PROTO || netCfg.protocol       || "TCP",
  TCP_PORT:          netCfg.tcp_port            || 5200,
  UDP_PORT:          netCfg.udp_port            || 5201,
  CONNECT_TIMEOUT:   netCfg.connect_timeout_ms  || 3000,
  RESPONSE_TIMEOUT:  netCfg.response_timeout_ms || 2000,
  WEB_PORT:          parseInt(process.env.PORT || netCfg.web_port || "8080"),
  DEBUG:             process.argv.includes("--debug"),
};

// ─── Novastar Protocol ────────────────────────────────────────────────────────

// Register addresses (from sarakusha/novastar AddressMapping.ts)
const REG = {
  SELF_TEST_MODE: 0x02000101,  // Write 1 byte: test pattern value
  GLOBAL_BRIGHTNESS: 0x02000001,
};

// Test pattern values (from sarakusha/novastar TestMode.ts enum)
const TEST_MODE = {
  off:   0,  // Normal display (Reserved1_Mode)
  red:   2,
  green: 3,
  blue:  4,
  white: 5,
  grid:  6,  // HorizonLine_Mode — horizontal line grid
};

// Card index constants
const CARD_ALL = 0xFFFF;

let serialCounter = 0;

/**
 * Build a Novastar write packet.
 * @param {number} cardIndex - 0-based card index, or CARD_ALL (0xFFFF)
 * @param {number} register  - 32-bit register address
 * @param {Buffer|number[]} data - bytes to write
 * @returns {Buffer}
 */
function buildWritePacket(cardIndex, register, data) {
  const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  const serial  = serialCounter++ & 0xFF;

  // Broadcast vs. addressed
  const dest = cardIndex === CARD_ALL ? 0xFF : 0x00;
  const port = cardIndex === CARD_ALL ? 0xFF : 0x00;

  const cardIdxBuf = Buffer.allocUnsafe(2);
  cardIdxBuf.writeUInt16LE(cardIndex, 0);

  const addrBuf = Buffer.allocUnsafe(4);
  addrBuf.writeUInt32LE(register, 0);

  const lenBuf = Buffer.allocUnsafe(2);
  lenBuf.writeUInt16LE(dataBuf.length, 0);

  // Protocol content (used for checksum): bytes 2..end-of-data
  const content = Buffer.concat([
    Buffer.from([0x00, serial, 0xFE, dest, 0x01, port]),  // status, serial, src, dst, devtype, port
    cardIdxBuf,
    Buffer.from([0x01, 0x00]),  // io_dir=Write, padding
    addrBuf,
    lenBuf,
    dataBuf,
  ]);

  // Checksum: sum all content bytes + 0x5555, store as uint16 LE
  let sum = 0;
  for (const b of content) sum += b;
  sum = (sum + 0x5555) & 0xFFFF;

  const crcBuf = Buffer.allocUnsafe(2);
  crcBuf.writeUInt16LE(sum, 0);

  return Buffer.concat([Buffer.from([0x55, 0xAA]), content, crcBuf]);
}

/**
 * Send a packet via TCP and wait for acknowledgment.
 * Resolves with {ok: true, response: Buffer} or {ok: false, error: string}
 */
function sendTCP(packet) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    let responded = false;
    let responseData = Buffer.alloc(0);

    const finish = (result) => {
      if (responded) return;
      responded = true;
      clearTimeout(connTimer);
      clearTimeout(respTimer);
      sock.destroy();
      resolve(result);
    };

    const connTimer = setTimeout(() => {
      finish({ ok: false, error: `Connection timeout to ${CONFIG.SENDING_CARD_IP}:${CONFIG.TCP_PORT}` });
    }, CONFIG.CONNECT_TIMEOUT);

    let respTimer;

    sock.on("error", (err) => finish({ ok: false, error: err.message }));

    sock.connect(CONFIG.TCP_PORT, CONFIG.SENDING_CARD_IP, () => {
      clearTimeout(connTimer);
      if (CONFIG.DEBUG) console.log(`[TCP] Connected. Sending: ${packet.toString("hex")}`);

      respTimer = setTimeout(() => {
        // No response is common — some firmware doesn't ACK test-mode writes
        finish({ ok: true, response: responseData, warning: "No response (may be normal)" });
      }, CONFIG.RESPONSE_TIMEOUT);

      sock.write(packet);
    });

    sock.on("data", (chunk) => {
      responseData = Buffer.concat([responseData, chunk]);
      if (CONFIG.DEBUG) console.log(`[TCP] Response: ${responseData.toString("hex")}`);
      // Minimal response is header(2) + content + crc(2) = at least 20 bytes
      if (responseData.length >= 20) {
        finish({ ok: true, response: responseData });
      }
    });
  });
}

/**
 * Send a packet via UDP (fire-and-forget — no reliable ACK).
 */
function sendUDP(packet) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    sock.send(packet, CONFIG.UDP_PORT, CONFIG.SENDING_CARD_IP, (err) => {
      sock.close();
      if (err) {
        resolve({ ok: false, error: err.message });
      } else {
        if (CONFIG.DEBUG) console.log(`[UDP] Sent: ${packet.toString("hex")}`);
        resolve({ ok: true, warning: "UDP — no ACK available" });
      }
    });
  });
}

function sendPacket(packet) {
  return CONFIG.PROTOCOL === "UDP" ? sendUDP(packet) : sendTCP(packet);
}

/**
 * Set test mode on one or all receiving cards.
 * @param {number|"all"} card  - card index (0-based) or "all"
 * @param {string}        mode - "red"|"green"|"blue"|"white"|"grid"|"off"
 */
async function setTestMode(card, mode) {
  const modeValue = TEST_MODE[mode];
  if (modeValue === undefined) throw new Error(`Unknown mode: ${mode}`);

  const cardIndex = card === "all" ? CARD_ALL : parseInt(card, 10);
  if (!Number.isInteger(cardIndex) || cardIndex < 0 || (cardIndex > 255 && cardIndex !== CARD_ALL)) {
    throw new Error(`Invalid card index: ${card}`);
  }

  const packet = buildWritePacket(cardIndex, REG.SELF_TEST_MODE, [modeValue]);

  if (CONFIG.DEBUG) {
    const cardStr = cardIndex === CARD_ALL ? "ALL" : cardIndex;
    console.log(`[CMD] setTestMode card=${cardStr} mode=${mode}(${modeValue}) reg=0x${REG.SELF_TEST_MODE.toString(16).padStart(8,"0")}`);
  }

  const result = await sendPacket(packet);
  return result;
}

// ─── Express Web Server ───────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

/**
 * POST /testmode
 * Body: { card: 0|1|2|...|"all", mode: "red"|"green"|"blue"|"white"|"grid"|"off" }
 * Response: { ok: bool, mode, card, message, warning? }
 */
app.post("/testmode", async (req, res) => {
  const { card, mode } = req.body;

  if (mode === undefined || card === undefined) {
    return res.status(400).json({ ok: false, error: "Missing required fields: card, mode" });
  }
  if (!Object.hasOwn(TEST_MODE, mode)) {
    return res.status(400).json({ ok: false, error: `Invalid mode. Use: ${Object.keys(TEST_MODE).join(", ")}` });
  }

  console.log(`[REQ] POST /testmode  card=${card}  mode=${mode}`);

  try {
    const result = await setTestMode(card, mode);
    const cardStr = card === "all" ? "all cards" : `card #${card}`;

    if (result.ok) {
      return res.json({
        ok: true,
        mode,
        card: card === "all" ? "all" : parseInt(card, 10),
        message: `${mode.toUpperCase()} set on ${cardStr}`,
        warning: result.warning,
        responseHex: result.response ? result.response.toString("hex") : null,
      });
    } else {
      return res.status(502).json({ ok: false, error: result.error });
    }
  } catch (err) {
    console.error(`[ERR] ${err.message}`);
    return res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * GET /status
 * Quick connectivity check — tries to connect to sending card.
 */
app.get("/status", async (req, res) => {
  if (CONFIG.PROTOCOL === "UDP") {
    return res.json({ ok: true, message: "UDP mode — no connectivity check available", config: CONFIG });
  }

  const check = new Promise((resolve) => {
    const sock = new net.Socket();
    const timer = setTimeout(() => { sock.destroy(); resolve(false); }, CONFIG.CONNECT_TIMEOUT);
    sock.on("error", () => { clearTimeout(timer); resolve(false); });
    sock.connect(CONFIG.TCP_PORT, CONFIG.SENDING_CARD_IP, () => {
      clearTimeout(timer);
      sock.destroy();
      resolve(true);
    });
  });

  const reachable = await check;
  res.json({
    ok: reachable,
    message: reachable
      ? `Sending card reachable at ${CONFIG.SENDING_CARD_IP}:${CONFIG.TCP_PORT}`
      : `Cannot reach sending card at ${CONFIG.SENDING_CARD_IP}:${CONFIG.TCP_PORT}`,
    config: {
      sendingCardIP: CONFIG.SENDING_CARD_IP,
      protocol: CONFIG.PROTOCOL,
      port: CONFIG.PROTOCOL === "TCP" ? CONFIG.TCP_PORT : CONFIG.UDP_PORT,
    },
  });
});

/**
 * GET /config
 * Returns current configuration (read-only, no secrets).
 */
app.get("/config", (req, res) => {
  res.json({
    sendingCardIP: CONFIG.SENDING_CARD_IP,
    protocol: CONFIG.PROTOCOL,
    tcpPort: CONFIG.TCP_PORT,
    udpPort: CONFIG.UDP_PORT,
    modes: Object.keys(TEST_MODE),
  });
});

/**
 * POST /config
 * Update sending card IP at runtime without restart.
 * Body: { sendingCardIP: "x.x.x.x" }
 */
app.post("/config", (req, res) => {
  const { sendingCardIP, protocol } = req.body;
  if (sendingCardIP) {
    const ipRx = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (!ipRx.test(sendingCardIP)) {
      return res.status(400).json({ ok: false, error: "Invalid IP address" });
    }
    CONFIG.SENDING_CARD_IP = sendingCardIP;
    console.log(`[CFG] Sending card IP updated to ${sendingCardIP}`);
  }
  if (protocol && (protocol === "TCP" || protocol === "UDP")) {
    CONFIG.PROTOCOL = protocol;
    console.log(`[CFG] Protocol updated to ${protocol}`);
  }
  res.json({ ok: true, sendingCardIP: CONFIG.SENDING_CARD_IP, protocol: CONFIG.PROTOCOL });
});

// ─── Processor State ─────────────────────────────────────────────────────────
// In-memory processor state. When protocol is wired up, this gets populated
// by real reads. For now it serves as the data model the UI renders from,
// replacing all hardcoded HTML in the UI.

const processorState = [
  {
    id: "vx4s",
    name: "VX4S",
    connection: { type: "usb", path: "/dev/ttyUSB0" },
    firmware: "4.5.2",
    status: "online",
    screens: ["Screen 1", "Screen 2"],
    input: { name: "HDMI 1", signal: true, resolution: "1920 \u00d7 1080 @ 60 Hz", shortRes: "1080p60" },
    brightness: 100,
    displayMode: "Normal",
    ports: [
      { num: 1, status: "healthy", tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 0 },
      { num: 2, status: "mismatch", tiles: 24, resolution: "192\u00d7384", model: "MRV330", firmware: "3.6.0", tempRange: "41\u201347\u00b0C", mismatches: 2 },
      { num: 3, status: "empty" },
      { num: 4, status: "empty", redundant: true }
    ],
    tileCount: 48,
    avgTemp: 42,
    mismatchCount: 2,
    calMode: "ON"
  },
  {
    id: "mctrl660",
    name: "MCTRL660",
    connection: { type: "net", ip: "192.168.0.12" },
    firmware: "3.2.0",
    status: "online",
    screens: ["Screen 1"],
    input: { name: "HDMI 1", signal: true, resolution: "1920 \u00d7 1080 @ 60 Hz", shortRes: "1080p60" },
    brightness: 80,
    displayMode: "Normal",
    ports: [
      { num: 1, status: "healthy", tiles: 6, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "36\u201340\u00b0C", mismatches: 0 },
      { num: 2, status: "healthy", tiles: 6, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "37\u201341\u00b0C", mismatches: 0 },
      { num: 3, status: "empty" },
      { num: 4, status: "empty" },
      { num: 5, status: "empty" },
      { num: 6, status: "empty" }
    ],
    tileCount: 12,
    avgTemp: 39,
    mismatchCount: 0,
    calMode: "ON"
  },
  {
    id: "vx2000",
    name: "VX2000",
    connection: { type: "net", ip: "192.168.0.22" },
    firmware: "2.1.4",
    status: "online",
    screens: ["Screen 1"],
    input: { name: "DP 1", signal: true, resolution: "3840 \u00d7 2160 @ 60 Hz", shortRes: "4K@60" },
    brightness: 75,
    displayMode: "Normal",
    ports: [
      { num: 1,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 0 },
      { num: 2,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "39\u201345\u00b0C", mismatches: 0 },
      { num: 3,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "37\u201343\u00b0C", mismatches: 0 },
      { num: 4,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 0 },
      { num: 5,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "40\u201346\u00b0C", mismatches: 0, redundant: true },
      { num: 6,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 0 },
      { num: 7,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "39\u201345\u00b0C", mismatches: 0 },
      { num: 8,  status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "37\u201343\u00b0C", mismatches: 0 },
      { num: 9,  status: "mismatch", tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.7.0", tempRange: "41\u201349\u00b0C", mismatches: 1 },
      { num: 10, status: "mismatch", tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "39\u201345\u00b0C", mismatches: 1 },
      { num: 11, status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 0 },
      { num: 12, status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "39\u201345\u00b0C", mismatches: 0 },
      { num: 13, status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "37\u201343\u00b0C", mismatches: 0 },
      { num: 14, status: "mismatch", tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "38\u201344\u00b0C", mismatches: 2 },
      { num: 15, status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "39\u201345\u00b0C", mismatches: 0 },
      { num: 16, status: "healthy",  tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.8.1", tempRange: "37\u201343\u00b0C", mismatches: 0 },
      { num: 17, status: "empty" },
      { num: 18, status: "mismatch", tiles: 24, resolution: "192\u00d7192", model: "MRV300", firmware: "3.6.0", tempRange: "43\u201351\u00b0C", mismatches: 1 },
      { num: 19, status: "empty" },
      { num: 20, status: "empty" }
    ],
    tileCount: 480,
    avgTemp: 44,
    mismatchCount: 4,
    calMode: "ON"
  }
];

/**
 * GET /api/processors
 * Returns the full processor state array. The UI renders entirely from this.
 * When protocol is wired, this will read live data from connected hardware.
 */
app.get("/api/processors", (req, res) => {
  res.json(processorState);
});

/**
 * GET /api/site-config
 * Returns site config (EDID presets, warning thresholds, defaults, etc.)
 * The UI renders config-driven elements from this.
 */
app.get("/api/site-config", (req, res) => {
  res.json(siteConfig);
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(CONFIG.WEB_PORT, "0.0.0.0", () => {
  const version = (siteConfig.device && siteConfig.device.version) || "dev";
  console.log("\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557");
  console.log("\u2551     NovaTool Diagnostic Server v" + version + "          \u2551");
  console.log("\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d");
  console.log(`\n  Web UI:        http://0.0.0.0:${CONFIG.WEB_PORT}`);
  console.log(`  Sending card:  ${CONFIG.SENDING_CARD_IP} (${CONFIG.PROTOCOL})`);
  console.log(`  Debug mode:    ${CONFIG.DEBUG}`);
  console.log(`  Config:        ${CONFIG_PATH}\n`);
  if (CONFIG.DEBUG) {
    console.log("  [DEBUG] Verbose packet logging enabled\n");
  }
});
