#!/usr/bin/env python3
"""
Novastar .pcapng Packet Analyzer
Parses a Wireshark capture of NovaLCT traffic and extracts all commands.

Usage:
    python3 parse_capture.py capture.pcapng
    python3 parse_capture.py capture.pcapng --verbose
    python3 parse_capture.py capture.pcapng --export-server
    python3 parse_capture.py capture.pcapng --timeline   (timestamped sequence — best for audio sync)

Requires: pip install scapy
"""

import sys
import argparse
import struct
from collections import defaultdict

try:
    from scapy.all import rdpcap, UDP, TCP, Raw, IP
except ImportError:
    print("ERROR: scapy not installed. Run: pip3 install scapy")
    sys.exit(1)


# ─── Protocol Constants ───────────────────────────────────────────────────────

NOVASTAR_PORTS = {5200, 5201}

HEADER_REQUEST  = 0xAA55  # bytes: 55 AA
HEADER_RESPONSE = 0x55AA  # bytes: AA 55

DEVICE_TYPES = {
    0x00: "SendingCard",
    0x01: "ReceivingCard",
    0x02: "FunctionCard",
}

IO_DIRECTION = {0: "Read", 1: "Write"}

# Known register addresses.
# Any address NOT in this dict is flagged as UNKNOWN in the output.
# Add new discoveries here after each capture session.
KNOWN_REGISTERS = {
    # Brightness
    0x02000001: "GlobalBrightness",
    0x02000002: "RedBrightness",
    0x02000003: "GreenBrightness",
    0x02000004: "BlueBrightness",

    # Display mode
    0x02000100: "KillMode",
    0x02000101: "SelfTestMode",
    0x02000102: "LockMode",
    0x02000190: "UCS512C_DisplayMode",
    0x03100101: "DisplayMode",

    # Test / diagnostics
    0x01000003: "TestPoint",
}

# TestMode enum values (from sarakusha/novastar TestMode.ts)
# Confirmed values marked [C], unconfirmed marked [?]
TEST_MODE_VALUES = {
    0:  "Normal/Off      [C]",
    1:  "Reserved        [?]",
    2:  "Red             [C]",
    3:  "Green           [C]",
    4:  "Blue            [C]",
    5:  "White           [C]",
    6:  "HorizonLine     [?]",
    7:  "VerticalLine    [?]",
    8:  "InclineLine     [?]",
    9:  "GrayIncrease    [?]",
    10: "Age             [?]",
    11: "HardwareScreen  [?]",
    16: "LogoTest        [?]",
}


# ─── Packet Model ─────────────────────────────────────────────────────────────

class NovaPkt:
    """Parsed Novastar protocol packet."""

    def __init__(self, raw: bytes, src_ip: str, dst_ip: str,
                 proto: str, timestamp: float):
        self.raw       = raw
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.proto     = proto
        self.timestamp = timestamp   # Unix epoch float from pcap
        self.valid     = False
        self.error     = ""
        self._parse()

    def _parse(self):
        b = self.raw
        if len(b) < 20:
            self.error = f"Too short ({len(b)} bytes)"
            return

        header = struct.unpack_from("<H", b, 0)[0]
        if header == HEADER_REQUEST:
            self.direction = "Request"
        elif header == HEADER_RESPONSE:
            self.direction = "Response"
        else:
            self.error = f"Bad header: {b[0]:02X} {b[1]:02X}"
            return

        self.status    = b[2]
        self.serial    = b[3]
        self.source    = b[4]
        self.dest      = b[5]
        self.dev_type  = b[6]
        self.port_byte = b[7]
        self.card_idx  = struct.unpack_from("<H", b, 8)[0]
        self.io_dir    = b[10]
        self.address   = struct.unpack_from("<I", b, 12)[0]
        self.data_len  = struct.unpack_from("<H", b, 16)[0]

        expected_total = 18 + self.data_len + 2
        if len(b) < expected_total:
            self.error = f"Truncated: need {expected_total}, have {len(b)}"
            return

        self.data       = b[18: 18 + self.data_len]
        crc_bytes       = b[18 + self.data_len: 18 + self.data_len + 2]
        self.crc_stored = struct.unpack_from("<H", crc_bytes)[0]

        content  = b[2: 18 + self.data_len]
        crc_calc = (sum(content) + 0x5555) & 0xFFFF
        self.crc_ok = (crc_calc == self.crc_stored)
        self.valid  = True

    @property
    def register_name(self):
        return KNOWN_REGISTERS.get(self.address, f"0x{self.address:08X}")

    @property
    def is_unknown_register(self):
        """True when this register address is not in our known list."""
        return self.address not in KNOWN_REGISTERS

    @property
    def card_str(self):
        return "ALL" if self.card_idx == 0xFFFF else str(self.card_idx)

    @property
    def data_hex(self):
        return " ".join(f"{b:02X}" for b in self.data)

    @property
    def raw_hex(self):
        return " ".join(f"{b:02X}" for b in self.raw)

    def __repr__(self):
        if not self.valid:
            return f"<InvalidPkt: {self.error}>"
        return (f"<NovaPkt {self.direction} card={self.card_str} "
                f"reg={self.register_name} io={IO_DIRECTION.get(self.io_dir,'?')} "
                f"data=[{self.data_hex}]>")


# ─── Loader ───────────────────────────────────────────────────────────────────

def load_packets(pcap_file: str) -> list:
    print(f"\n[*] Loading {pcap_file} ...")
    raw_pkts = rdpcap(pcap_file)
    print(f"[*] Total packets in capture: {len(raw_pkts)}")

    nova_pkts = []
    skipped   = 0

    for pkt in raw_pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue

        proto         = None
        sport, dport  = 0, 0

        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = "UDP"
        elif pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = "TCP"
        else:
            continue

        if sport not in NOVASTAR_PORTS and dport not in NOVASTAR_PORTS:
            continue

        raw = bytes(pkt[Raw])
        if len(raw) < 2:
            continue

        ts  = float(pkt.time)
        np  = NovaPkt(raw, pkt[IP].src, pkt[IP].dst, proto, ts)
        if np.valid:
            nova_pkts.append(np)
        else:
            skipped += 1

    print(f"[*] Novastar packets: {len(nova_pkts)} valid, {skipped} invalid/skipped")
    return nova_pkts


# ─── Analysis Sections ────────────────────────────────────────────────────────

def _divider(title=""):
    if title:
        print("\n" + "═" * 72)
        print(f" {title}")
        print("═" * 72)
    else:
        print("─" * 72)


def section_unknown_registers(pkts: list):
    """
    Flag any register address we haven't seen before.
    This is the primary tool for discovering new registers from a capture.
    """
    _divider("*** UNKNOWN REGISTERS — NEW DISCOVERIES ***")

    writes = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"
              and p.is_unknown_register]
    reads  = [p for p in pkts if p.io_dir == 0 and p.direction == "Request"
              and p.is_unknown_register]

    if not writes and not reads:
        print("\n  None — all registers in this capture are already known.")
        return

    # Group by address
    by_addr = defaultdict(list)
    for p in writes + reads:
        by_addr[p.address].append(p)

    print(f"\n  Found {len(by_addr)} unknown register address(es).\n")
    print(f"  {'Address':<14} {'IO':<7} {'Data (hex)':<24} {'Times seen'}")
    print(f"  {'─'*14} {'─'*7} {'─'*24} {'─'*10}")

    for addr in sorted(by_addr):
        entries = by_addr[addr]
        # Show unique data values seen for this address
        unique_data = list({p.data_hex for p in entries})
        io_types    = list({IO_DIRECTION.get(p.io_dir, "?") for p in entries})
        print(f"\n  *** 0x{addr:08X}  "
              f"io={'/'.join(io_types)}  "
              f"seen {len(entries)}x")
        for d in unique_data[:8]:
            print(f"       data: [{d}]"
                  f"  decimal: {[int(x,16) for x in d.split()] if d else []}")
        if len(unique_data) > 8:
            print(f"       ... and {len(unique_data)-8} more unique values")

    print(f"\n  ACTION: Add these to KNOWN_REGISTERS in this script after")
    print(f"  confirming what each one does from your session narration.")


def section_known_writes(pkts: list, verbose: bool):
    _divider("ALL UNIQUE WRITE COMMANDS (known registers)")

    writes = [p for p in pkts
              if p.io_dir == 1 and p.direction == "Request"
              and not p.is_unknown_register]

    if not writes:
        print("\n  None found.")
        return

    seen       = {}
    by_register = defaultdict(list)

    for p in writes:
        key = (p.address, p.data_hex, p.card_idx)
        if key not in seen:
            seen[key] = p

    for (addr, data_hex, card_idx), p in seen.items():
        by_register[addr].append((card_idx, data_hex, p))

    for addr in sorted(by_register):
        reg_name = KNOWN_REGISTERS.get(addr, f"0x{addr:08X}")
        entries  = by_register[addr]
        print(f"\n  Register: {reg_name} (0x{addr:08X})")
        for card_idx, data_hex, p in sorted(entries):
            card_str = "ALL" if card_idx == 0xFFFF else f"card #{card_idx}"
            note = ""
            if addr == 0x02000101 and p.data:
                raw_val  = p.data[0]
                mode_str = TEST_MODE_VALUES.get(raw_val, f"Unknown(0x{raw_val:02X})")
                note = f"  → {mode_str}"
            print(f"    card={card_str}  data=[{data_hex}]{note}")
            if verbose:
                print(f"      raw: {p.raw_hex}")


def section_test_patterns(pkts: list):
    _divider("TEST PATTERN COMMANDS (SelfTestMode 0x02000101)")

    writes = [p for p in pkts
              if p.io_dir == 1 and p.direction == "Request"
              and p.address == 0x02000101]

    if not writes:
        print("\n  No writes to 0x02000101 found.")
        print("  Check unknown registers section — address may differ on this processor.")
        return

    seen = {}
    for p in writes:
        val = p.data[0] if p.data else 0xFF
        if val not in seen:
            seen[val] = p

    print(f"\n  {'Mode Name':<28} {'Val':>4}   {'Card':>6}   {'CRC':>5}   Raw Packet")
    print(f"  {'─'*28} {'─'*4}   {'─'*6}   {'─'*5}   {'─'*48}")

    for val in sorted(seen):
        p         = seen[val]
        mode_name = TEST_MODE_VALUES.get(val, f"UNKNOWN (0x{val:02X}) ***")
        crc_str   = "OK" if p.crc_ok else "FAIL"
        print(f"  {mode_name:<28} {val:>4}   {p.card_str:>6}   {crc_str:>5}   {p.raw_hex}")


def section_timeline(pkts: list, verbose: bool):
    """
    Timestamped chronological sequence of all write commands.
    Timestamps are relative to the first packet in the capture —
    use these to sync against your voice memo narration.
    """
    _divider("TIMESTAMPED COMMAND TIMELINE  (sync with voice memo)")

    writes = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]

    if not writes:
        print("\n  No write commands found.")
        return

    t0 = pkts[0].timestamp  # time of first packet in capture

    print(f"\n  T+0.000 = first packet in capture")
    print(f"  Showing all {len(writes)} write commands\n")
    print(f"  {'T+sec':>8}  {'Register':<30} {'Card':>6}  Data              Note")
    print(f"  {'─'*8}  {'─'*30} {'─'*6}  {'─'*18}  {'─'*28}")

    for p in writes:
        elapsed   = p.timestamp - t0
        reg_name  = p.register_name
        unknown   = "*** UNKNOWN ***" if p.is_unknown_register else ""

        note = unknown
        if not note and p.address == 0x02000101 and p.data:
            val  = p.data[0]
            note = TEST_MODE_VALUES.get(val, f"Unknown mode {val}")
        elif not note and p.address == 0x02000001 and p.data:
            # GlobalBrightness — show as percentage approximation
            val     = p.data[0]
            pct_approx = round(val / 255 * 100)
            note    = f"~{pct_approx}%"

        print(f"  {elapsed:>8.3f}  {reg_name:<30} {p.card_str:>6}  "
              f"[{p.data_hex:<16}]  {note}")

        if verbose:
            print(f"           raw: {p.raw_hex}")


def section_topology(pkts: list):
    _divider("NETWORK TOPOLOGY")

    flows = set((p.src_ip, p.dst_ip, p.proto) for p in pkts)
    print()
    for src, dst, proto in sorted(flows):
        print(f"  {src:<16} → {dst:<16}  ({proto})")

    dst_ips = [p.dst_ip for p in pkts if p.direction == "Request"]
    if dst_ips:
        sending_card_ip = max(set(dst_ips), key=dst_ips.count)
        print(f"\n  Likely sending card IP: {sending_card_ip}")
        protos = set(p.proto for p in pkts)
        proto  = "TCP" if "TCP" in protos else "UDP"
        print(f"  Protocol: {proto}  Port: {5200 if proto == 'TCP' else 5201}")


def section_server_config(pkts: list):
    """Export JSON block for pasting into server.js."""
    import json as jsonlib

    _divider("SERVER.JS CONFIG EXPORT")

    writes     = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]
    test_pkts  = [p for p in writes if p.address == 0x02000101]

    config = {
        "selfTestModeRegister": "0x02000101",
        "capturedPackets": {},
        "confirmedModes": {},
    }

    for p in test_pkts:
        if p.data:
            val       = p.data[0]
            name      = TEST_MODE_VALUES.get(val, f"unknown_{val}")
            clean     = name.split("[")[0].strip().lower().replace("/", "_").replace(" ", "_")
            config["confirmedModes"][clean] = val
            config["capturedPackets"][clean] = list(p.raw)

    if config["capturedPackets"]:
        print("\n// ── Paste into server.js TEST_MODE constants ──")
        print(jsonlib.dumps(config, indent=2))
    else:
        print("\n  No test pattern packets found in this capture.")
        print("  Run capture 02 (test patterns) and use --export-server on that file.")


def section_summary(pkts: list):
    writes   = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]
    reads    = [p for p in pkts if p.io_dir == 0 and p.direction == "Request"]
    resps    = [p for p in pkts if p.direction == "Response"]
    unknowns = [p for p in pkts if p.is_unknown_register]

    duration = pkts[-1].timestamp - pkts[0].timestamp if len(pkts) > 1 else 0

    print(f"\n  Capture duration : {duration:.1f} seconds")
    print(f"  Total packets    : {len(pkts)}")
    print(f"  Write commands   : {len(writes)}")
    print(f"  Read commands    : {len(reads)}")
    print(f"  Responses        : {len(resps)}")
    unknown_addrs = len({p.address for p in unknowns})
    if unknown_addrs:
        print(f"  *** UNKNOWN regs : {unknown_addrs} address(es) — see Unknown Registers section ***")
    else:
        print(f"  Unknown registers: 0  (all known)")


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Novastar pcapng analyzer with timestamp and unknown-register detection"
    )
    parser.add_argument("pcap",
        help="Path to .pcapng capture file")
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Show raw hex bytes for every packet")
    parser.add_argument("--export-server", action="store_true",
        help="Output JSON config block for server.js (use with test pattern capture)")
    parser.add_argument("--timeline", action="store_true",
        help="Show timestamped sequence — best for syncing with voice memo narration")
    args = parser.parse_args()

    pkts = load_packets(args.pcap)
    if not pkts:
        print("\n[!] No Novastar packets found. Check that traffic on ports 5200/5201")
        print("    is present in the capture and the mirror port is correct.")
        sys.exit(1)

    _divider("SUMMARY")
    section_summary(pkts)

    # Unknown registers first — highest priority new information
    section_unknown_registers(pkts)

    section_test_patterns(pkts)
    section_known_writes(pkts, verbose=args.verbose)

    if args.timeline:
        section_timeline(pkts, verbose=args.verbose)
    else:
        # Always show a brief timeline even without the flag
        _divider("COMMAND TIMELINE  (use --timeline for full timestamped view)")
        writes = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]
        t0     = pkts[0].timestamp
        print(f"\n  {'T+sec':>8}  {'Register':<30} Data")
        print(f"  {'─'*8}  {'─'*30} {'─'*20}")
        for p in writes[:40]:
            unknown = " ***UNKNOWN***" if p.is_unknown_register else ""
            print(f"  {p.timestamp-t0:>8.3f}  {p.register_name:<30} [{p.data_hex}]{unknown}")
        if len(writes) > 40:
            print(f"\n  ... {len(writes)-40} more — run with --timeline to see all")

    section_topology(pkts)

    if args.export_server:
        section_server_config(pkts)

    print("\n\n[✓] Analysis complete.\n")


if __name__ == "__main__":
    main()
