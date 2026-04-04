#!/usr/bin/env python3
"""
Novastar .pcapng Packet Analyzer
Parses a Wireshark capture of NovaLCT traffic and extracts test pattern commands.

Usage:
    python3 parse_capture.py capture.pcapng
    python3 parse_capture.py capture.pcapng --verbose
    python3 parse_capture.py capture.pcapng --export-server

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

# Key register addresses (from sarakusha/novastar AddressMapping.ts)
KNOWN_REGISTERS = {
    0x02000001: "GlobalBrightness",
    0x02000002: "RedBrightness",
    0x02000003: "GreenBrightness",
    0x02000004: "BlueBrightness",
    0x02000100: "KillMode",
    0x02000101: "SelfTestMode",
    0x02000102: "LockMode",
    0x02000190: "UCS512C_DisplayMode",
    0x01000003: "TestPoint",
    0x03100101: "DisplayMode",
}

# TestMode enum values (from sarakusha/novastar TestMode.ts)
TEST_MODE_VALUES = {
    0:  "Normal/Off",
    1:  "Reserved",
    2:  "Red",
    3:  "Green",
    4:  "Blue",
    5:  "White",
    6:  "HorizonLine (Grid)",
    7:  "VerticalLine",
    8:  "InclineLine",
    9:  "GrayIncrease",
    10: "Age",
    11: "HardwareScreen",
    16: "LogoTest",
}


# ─── Packet Parser ────────────────────────────────────────────────────────────

class NovaPkt:
    """Parsed Novastar protocol packet."""
    MIN_SIZE = 20  # header(2) + status(1) + serial(1) + src(1) + dst(1) +
                   # devtype(1) + port(1) + card_idx(2) + io(1) + pad(1) +
                   # addr(4) + len(2) + min_data(0) + crc(2) = 18, data>=0

    def __init__(self, raw: bytes, src_ip: str, dst_ip: str, proto: str):
        self.raw     = raw
        self.src_ip  = src_ip
        self.dst_ip  = dst_ip
        self.proto   = proto
        self.valid   = False
        self.error   = ""
        self._parse()

    def _parse(self):
        b = self.raw
        if len(b) < 20:
            self.error = f"Too short ({len(b)} bytes)"; return

        header = struct.unpack_from("<H", b, 0)[0]
        if header == HEADER_REQUEST:
            self.direction = "Request"
        elif header == HEADER_RESPONSE:
            self.direction = "Response"
        else:
            self.error = f"Bad header: {b[0]:02X} {b[1]:02X}"; return

        self.status    = b[2]
        self.serial    = b[3]
        self.source    = b[4]
        self.dest      = b[5]
        self.dev_type  = b[6]
        self.port_byte = b[7]
        self.card_idx  = struct.unpack_from("<H", b, 8)[0]
        self.io_dir    = b[10]
        # b[11] = padding
        self.address   = struct.unpack_from("<I", b, 12)[0]
        self.data_len  = struct.unpack_from("<H", b, 16)[0]

        expected_total = 18 + self.data_len + 2
        if len(b) < expected_total:
            self.error = f"Truncated: need {expected_total}, have {len(b)}"; return

        self.data = b[18 : 18 + self.data_len]
        crc_bytes = b[18 + self.data_len : 18 + self.data_len + 2]
        self.crc_stored = struct.unpack_from("<H", crc_bytes)[0]

        # Verify checksum: sum of content bytes (offset 2..18+data_len) + 0x5555
        content = b[2 : 18 + self.data_len]
        crc_calc = (sum(content) + 0x5555) & 0xFFFF
        self.crc_ok = (crc_calc == self.crc_stored)

        self.valid = True

    @property
    def register_name(self):
        return KNOWN_REGISTERS.get(self.address, f"0x{self.address:08X}")

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


# ─── Main Analysis ────────────────────────────────────────────────────────────

def extract_novastar_packets(pcap_file: str) -> list[NovaPkt]:
    """Load pcap and extract all Novastar packets from ports 5200/5201."""
    print(f"\n[*] Loading {pcap_file} ...")
    pkts = rdpcap(pcap_file)
    print(f"[*] Total packets in capture: {len(pkts)}")

    nova_pkts = []
    skipped = 0

    for pkt in pkts:
        if not (pkt.haslayer(IP) and pkt.haslayer(Raw)):
            continue

        proto = None
        sport, dport = 0, 0

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

        np = NovaPkt(raw, pkt[IP].src, pkt[IP].dst, proto)
        if np.valid:
            nova_pkts.append(np)
        else:
            skipped += 1

    print(f"[*] Novastar packets parsed: {len(nova_pkts)} valid, {skipped} invalid/skipped")
    return nova_pkts


def analyze_packets(pkts: list[NovaPkt], verbose: bool = False):
    """Analyze and print packet summary tables."""

    # ── 1. All unique write commands ────────────────────────────────────────
    print("\n" + "═"*72)
    print(" ALL UNIQUE WRITE COMMANDS (register → value)")
    print("═"*72)

    seen = {}  # (address, data_hex) -> NovaPkt
    writes = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]

    for p in writes:
        key = (p.address, p.data_hex, p.card_idx)
        if key not in seen:
            seen[key] = p

    # Group by register
    by_register = defaultdict(list)
    for (addr, data_hex, card_idx), p in seen.items():
        by_register[addr].append((card_idx, data_hex, p))

    for addr in sorted(by_register):
        reg_name = KNOWN_REGISTERS.get(addr, f"0x{addr:08X}")
        entries = by_register[addr]
        print(f"\n  Register: {reg_name} (0x{addr:08X})")
        for card_idx, data_hex, p in sorted(entries):
            card_str = "ALL" if card_idx == 0xFFFF else f"card #{card_idx}"
            note = ""
            if addr == 0x02000101 and p.data:
                note = f"  → {TEST_MODE_VALUES.get(p.data[0], '?')}"
            print(f"    card={card_str}  data=[{data_hex}]{note}")
            if verbose:
                print(f"      raw hex: {p.raw_hex}")

    # ── 2. Test pattern commands specifically ───────────────────────────────
    print("\n" + "═"*72)
    print(" TEST PATTERN COMMANDS (SelfTestMode register 0x02000101)")
    print("═"*72)

    test_writes = [p for p in writes if p.address == 0x02000101]
    if not test_writes:
        # Try nearby registers in case address differs
        print("\n  [!] No writes to 0x02000101 found. Checking all registers for pattern data...")
        for addr, entries in by_register.items():
            for card_idx, data_hex, p in entries:
                if p.data and p.data[0] in TEST_MODE_VALUES and p.data[0] > 0:
                    print(f"  Possible test write: reg=0x{addr:08X} data=[{data_hex}]")
    else:
        seen_test = {}
        for p in test_writes:
            val = p.data[0] if p.data else 0xFF
            if val not in seen_test:
                seen_test[val] = p

        print(f"\n  {'Mode Name':<22} {'Value':>5}   {'Card':>6}   Raw Packet Hex")
        print(f"  {'-'*22} {'-'*5}   {'-'*6}   {'-'*40}")
        for val in sorted(seen_test):
            p = seen_test[val]
            mode_name = TEST_MODE_VALUES.get(val, f"Unknown(0x{val:02X})")
            print(f"  {mode_name:<22} {val:>5}   {p.card_str:>6}   {p.raw_hex}")

    # ── 3. Sequence timeline ─────────────────────────────────────────────────
    print("\n" + "═"*72)
    print(" COMMAND SEQUENCE (chronological write commands)")
    print("═"*72)
    print(f"\n  {'#':>4}  {'Register':<28} {'Card':>6}  {'IO':>5}  Data")
    print(f"  {'─'*4}  {'─'*28} {'─'*6}  {'─'*5}  ─────────────────────")
    for i, p in enumerate(writes[:100], 1):  # first 100
        print(f"  {i:>4}  {p.register_name:<28} {p.card_str:>6}  "
              f"{IO_DIRECTION.get(p.io_dir,'?'):>5}  [{p.data_hex}]")
    if len(writes) > 100:
        print(f"  ... ({len(writes)-100} more commands)")

    # ── 4. Unique IPs / topology ─────────────────────────────────────────────
    print("\n" + "═"*72)
    print(" NETWORK TOPOLOGY")
    print("═"*72)
    flows = set((p.src_ip, p.dst_ip, p.proto) for p in pkts)
    for src, dst, proto in sorted(flows):
        print(f"  {src} → {dst}  ({proto})")

    # ── 5. Sending card IP / port guess ──────────────────────────────────────
    print("\n" + "═"*72)
    print(" SUGGESTED server.js CONFIGURATION")
    print("═"*72)
    dst_ips = [p.dst_ip for p in pkts if p.direction == "Request"]
    if dst_ips:
        sending_card_ip = max(set(dst_ips), key=dst_ips.count)
        print(f"\n  SENDING_CARD_IP = '{sending_card_ip}'")
    protos = set(p.proto for p in pkts)
    proto_str = "TCP" if "TCP" in protos else "UDP"
    print(f"  PROTOCOL = '{proto_str}'")
    print(f"  PORT = {5200 if proto_str == 'TCP' else 5201}")


def export_server_config(pkts: list[NovaPkt]):
    """Print a JSON block suitable for copy-pasting into server.js."""
    import json

    writes = [p for p in pkts if p.io_dir == 1 and p.direction == "Request"]
    test_writes = [p for p in writes if p.address == 0x02000101]

    config = {
        "selfTestModeRegister": "0x02000101",
        "modes": {}
    }

    # Pull from capture if available, else use known defaults
    found = {}
    for p in test_writes:
        if p.data:
            val = p.data[0]
            name = TEST_MODE_VALUES.get(val, f"unknown_{val}")
            found[name] = list(p.raw)

    if found:
        config["capturedPackets"] = found
        print("\n// ── Captured test packets (paste into server.js) ──")
        print(json.dumps(config, indent=2))
    else:
        print("\n// No test pattern packets found in capture — using protocol defaults")
        print("// Run the analyzer again with the capture file containing test patterns")


def main():
    parser = argparse.ArgumentParser(description="Novastar pcapng packet analyzer")
    parser.add_argument("pcap", help="Path to .pcapng capture file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show raw hex for every packet")
    parser.add_argument("--export-server", action="store_true",
                        help="Output JSON config block for server.js")
    args = parser.parse_args()

    pkts = extract_novastar_packets(args.pcap)
    if not pkts:
        print("\n[!] No Novastar packets found. Check that the capture contains")
        print("    traffic on ports 5200 or 5201.")
        sys.exit(1)

    analyze_packets(pkts, verbose=args.verbose)

    if args.export_server:
        export_server_config(pkts)

    print("\n[✓] Analysis complete.\n")


if __name__ == "__main__":
    main()
