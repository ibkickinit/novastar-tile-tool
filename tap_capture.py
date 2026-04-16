#!/usr/bin/env python3
"""
Novastar dual-capture correlation tool.

Watches two interfaces simultaneously:
  --mgmt-iface  USB NIC on switch mirror port — sees Viplex commands to TB10
  --tile-iface  USB TAP monitor port — sees TB10 → LED tile traffic

When a Novastar protocol command is detected on the management side, the tool
logs what was sent (register address, data) and snapshots tile frames before
and after to show what changed in the output stream.

Usage:
  # Find your interfaces first:
  python3 tap_capture.py --list-ifaces

  # Run dual capture — fire commands from Viplex whenever ready:
  python3 tap_capture.py --mgmt-iface en9 --tile-iface en10

  # Save pcapng for Wireshark post-analysis:
  python3 tap_capture.py --mgmt-iface en9 --tile-iface en10 --out session.pcapng

Setup reminder:
  Switch mirror: TB10 management port → switch port 1
                 Mac USB NIC (en9)    → switch port 2  (mirror of port 1)
  TAP:           TB10 tile output → TAP → tile
                 TAP monitor port → Mac (en10 or similar)
"""

import os, sys, struct, fcntl, time, select, socket, threading, argparse
import collections, subprocess
from typing import Optional, Tuple, List

# VX1000 tile destination MACs (confirmed from 2026-04-15 capture)
# 09:1e:bf:bf:bf:bf — pixel data frames (ethertype 0xbfbf)
# 09:1e:00:00:00:00 — sync/control frames (ethertype 0x0000)
# Legacy TB10 MAC: 09:87:00:00:00:00 (not used by VX1000)
NOVA_TILE_DSTS = {
    bytes.fromhex('091ebfbfbfbf'): 'pixel',
    bytes.fromhex('091e00000000'): 'sync',
    bytes.fromhex('098700000000'): 'pixel',   # TB10 legacy, keep for compat
}
MGMT_PORT = 5200

# Known register addresses
REGISTERS = {
    0x02000101: 'SelfTestMode',
    0x02000100: 'KillMode',
    0x02000001: 'GlobalBrightness',
}
TEST_MODE_NAMES = {0: 'Off', 2: 'Red', 3: 'Green', 4: 'Blue', 5: 'White', 6: 'Grid/HorizLine', 7: 'VertLine'}

# ── BPF ──────────────────────────────────────────────────────────────────────

BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSBLEN     = 0xC0044266
BIOCSHDRCMPLT = 0x80044275
BIOCPROMISC   = 0x20004269

def open_bpf(iface: str) -> Tuple[int, int]:
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            try:
                fcntl.ioctl(fd, BIOCSBLEN, struct.pack('I', 1048576))  # 1MB buffer (must be before BIOCSETIF)
            except OSError:
                pass  # non-fatal; kernel may cap or ignore
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCPROMISC, struct.pack('I', 1))
            buflen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, b'\x00'*4))[0]
            print(f'[BPF] /dev/bpf{i} → {iface}  (buflen={buflen})')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError(f'No BPF device available for {iface}')

def read_bpf(fd: int, buflen: int, timeout: float = 0.05) -> List[bytes]:
    rdy, _, _ = select.select([fd], [], [], timeout)
    if not rdy:
        return []
    buf = os.read(fd, buflen)
    frames = []
    off = 0
    while off < len(buf):
        if off + 18 > len(buf):
            break
        caplen, _, hdrlen = struct.unpack_from('IIH', buf, off + 8)
        frames.append(buf[off + hdrlen: off + hdrlen + caplen])
        total = hdrlen + caplen
        off += (total + 3) & ~3
    return frames

# ── pcapng writer ─────────────────────────────────────────────────────────────

PCAPNG_MAGIC    = 0x0A0D0D0A
PCAPNG_BOM      = 0x1A2B3C4D
LINKTYPE_EN10MB = 1

def _pad4(n): return (n + 3) & ~3

def _pcapng_shb():
    body  = struct.pack('<IHH', PCAPNG_BOM, 1, 0)
    body += struct.pack('<q', -1)
    total = 12 + len(body)
    return struct.pack('<II', PCAPNG_MAGIC, total) + body + struct.pack('<I', total)

def _pcapng_idb(name: str = '', snaplen: int = 65535):
    body = struct.pack('<HHI', LINKTYPE_EN10MB, 0, snaplen)
    # Add interface name option if given
    if name:
        name_bytes = name.encode()
        opt = struct.pack('<HH', 2, len(name_bytes)) + name_bytes
        opt += b'\x00' * (_pad4(len(name_bytes)) - len(name_bytes))
        opt += struct.pack('<HH', 0, 0)   # end of options
        body += opt
    total = 12 + len(body)
    return struct.pack('<II', 2, total) + body + struct.pack('<I', total)

def _pcapng_epb(iface_id: int, ts_us: int, frame: bytes):
    caplen = len(frame)
    padded = _pad4(caplen)
    body   = struct.pack('<I', iface_id)
    body  += struct.pack('<II', (ts_us >> 32) & 0xFFFFFFFF, ts_us & 0xFFFFFFFF)
    body  += struct.pack('<II', caplen, caplen)
    body  += frame + b'\x00' * (padded - caplen)
    total  = 12 + len(body)
    return struct.pack('<II', 6, total) + body + struct.pack('<I', total)

class PcapngWriter:
    """Writes a pcapng with two named interfaces: 0=management, 1=tile."""
    def __init__(self, path: str, mgmt_iface: str, tile_iface: str):
        self._f    = open(path, 'wb')
        self._lock = threading.Lock()
        self._f.write(_pcapng_shb())
        self._f.write(_pcapng_idb(f'mgmt ({mgmt_iface})'))
        self._f.write(_pcapng_idb(f'tile ({tile_iface})'))
        print(f'[PCAP] Writing to {path}  (iface 0=mgmt, 1=tile)')

    def write(self, iface_id: int, frame: bytes):
        ts_us = int(time.time() * 1_000_000)
        block = _pcapng_epb(iface_id, ts_us, frame)
        with self._lock:
            self._f.write(block)

    def close(self):
        self._f.flush()
        self._f.close()

# ── Novastar management protocol decoder ─────────────────────────────────────

def decode_nova_mgmt(tcp_payload: bytes) -> Optional[dict]:
    """
    Decode a Novastar protocol packet from a TCP payload.
    Returns a dict with the decoded fields, or None if not a valid packet.
    Handles multiple packets concatenated in one TCP segment.
    """
    results = []
    pos = 0
    while pos < len(tcp_payload) - 18:
        if tcp_payload[pos] != 0x55 or tcp_payload[pos+1] != 0xAA:
            pos += 1
            continue
        try:
            status   = tcp_payload[pos+2]
            serial   = tcp_payload[pos+3]
            src      = tcp_payload[pos+4]
            dst      = tcp_payload[pos+5]
            dev_type = tcp_payload[pos+6]
            port     = tcp_payload[pos+7]
            card_idx = struct.unpack_from('<H', tcp_payload, pos+8)[0]
            io_dir   = tcp_payload[pos+10]   # 0x01=write, 0x00=read
            address  = struct.unpack_from('<I', tcp_payload, pos+12)[0]
            data_len = struct.unpack_from('<H', tcp_payload, pos+16)[0]

            if pos + 18 + data_len + 2 > len(tcp_payload):
                break

            data = tcp_payload[pos+18: pos+18+data_len]

            reg_name  = REGISTERS.get(address, f'0x{address:08X}')
            direction = 'WRITE' if io_dir == 0x01 else 'READ'
            card_str  = 'ALL' if card_idx == 0xFFFF else str(card_idx)

            decoded = {
                'direction': direction,
                'address':   address,
                'reg_name':  reg_name,
                'card':      card_str,
                'data':      data,
                'data_hex':  data.hex(),
                'serial':    serial,
            }

            # Human-readable value interpretation
            if address == 0x02000101 and data_len == 1:
                val = data[0]
                decoded['value_str'] = f'TestMode={TEST_MODE_NAMES.get(val, val)}'
            elif address == 0x02000001 and data_len >= 1:
                decoded['value_str'] = f'Brightness={data[0]}'
            elif address == 0x02000100 and data_len == 1:
                decoded['value_str'] = f'KillMode={data[0]}'
            else:
                decoded['value_str'] = data.hex()

            results.append(decoded)
            pos += 18 + data_len + 2   # skip checksum

        except Exception:
            pos += 1

    return results if results else None

def extract_tcp_payload(frame: bytes) -> Optional[bytes]:
    """Extract TCP payload from a raw Ethernet frame, or None if not TCP."""
    if len(frame) < 14:
        return None
    etype = frame[12:14]
    if etype != b'\x08\x00':   # IPv4 only
        return None
    ip = frame[14:]
    if len(ip) < 20:
        return None
    proto   = ip[9]
    if proto != 6:             # TCP only
        return None
    ihl     = (ip[0] & 0x0F) * 4
    tcp     = ip[ihl:]
    if len(tcp) < 20:
        return None
    dport   = struct.unpack_from('!H', tcp, 2)[0]
    sport   = struct.unpack_from('!H', tcp, 0)[0]
    if dport != MGMT_PORT and sport != MGMT_PORT:
        return None
    tcp_hdr = (tcp[12] >> 4) * 4
    payload = tcp[tcp_hdr:]
    return payload if payload else None

# ── Tile frame helpers ────────────────────────────────────────────────────────

def mac(b: bytes) -> str:
    return ':'.join(f'{x:02x}' for x in b)

def hexdump(b: bytes, width: int = 48) -> str:
    return ' '.join(f'{x:02x}' for x in b[:width]) + ('...' if len(b) > width else '')

def decode_tile_frame(frame: bytes) -> Optional[dict]:
    if len(frame) < 14:
        return None
    dst     = frame[0:6]
    src     = frame[6:12]
    etype   = frame[12:14].hex()
    payload = frame[14:]
    if dst in NOVA_TILE_DSTS:
        frame_type = NOVA_TILE_DSTS[dst]
        direction  = f'VX1000→TILE ({frame_type})'
    elif src in NOVA_TILE_DSTS:
        frame_type = NOVA_TILE_DSTS[src]
        direction  = f'TILE→VX1000 ({frame_type})'
    else:
        return None   # not a Novastar tile frame
    return {
        'direction': direction,
        'dst':       mac(dst),
        'src':       mac(src),
        'etype':     etype,
        'frame_len': len(frame),
        'payload':   payload,
        'all_zero':  not any(payload),
    }

def color_sniff(payload: bytes) -> str:
    """Return a short color description for a payload."""
    if not payload or len(payload) < 6:
        return '(empty)'
    for offset in range(3):
        triplets = []
        for i in range(offset, min(len(payload) - 2, offset + 120), 3):
            triplets.append((payload[i], payload[i+1], payload[i+2]))
        if not triplets:
            continue
        unique = set(triplets)
        if len(unique) == 1:
            r, g, b = triplets[0]
            return f'SOLID RGB=({r},{g},{b})'
        if len(unique) <= 4:
            return f'{len(unique)} unique RGB triplets: {list(unique)[:4]}'
    freq = collections.Counter(payload[:96])
    top3 = [(hex(k), v) for k, v in freq.most_common(3)]
    return f'top bytes {top3}'

def diff_payloads(before: bytes, after: bytes) -> str:
    """One-line diff summary."""
    if not before or not after:
        return '(no data)'
    n     = min(len(before), len(after))
    diffs = [i for i in range(n) if before[i] != after[i]]
    if not diffs:
        return 'NO CHANGE'
    pct = 100 * len(diffs) / n
    stride_str = ''
    if len(diffs) >= 4:
        gaps   = [diffs[i+1] - diffs[i] for i in range(min(len(diffs)-1, 20))]
        common = collections.Counter(gaps).most_common(1)[0]
        stride_str = f'  stride={common[0]}B'
    return f'{len(diffs)}/{n} bytes changed ({pct:.0f}%){stride_str}'

# ── Dual capture engine ───────────────────────────────────────────────────────

# How long (seconds) of tile frames to keep as the "before" window for comparison
BEFORE_WINDOW = 1.0
AFTER_WINDOW  = 1.5

class DualCapture:
    def __init__(self, fd_mgmt, bl_mgmt, fd_tile, bl_tile, writer: Optional[PcapngWriter]):
        self._fd_mgmt  = fd_mgmt
        self._bl_mgmt  = bl_mgmt
        self._fd_tile  = fd_tile
        self._bl_tile  = bl_tile
        self._writer   = writer
        self._stop     = threading.Event()
        self._lock     = threading.Lock()

        # Rolling buffer of (timestamp, frame_dict) for tile frames
        self._tile_buf: list[tuple[float, dict]] = []

        # Stats
        self._mgmt_count = 0
        self._tile_count = 0
        self._cmd_count  = 0

        # Track unique tile frame types seen
        self._tile_first_seen: dict[tuple, dict] = {}

    def _mgmt_loop(self):
        while not self._stop.is_set():
            for raw in read_bpf(self._fd_mgmt, self._bl_mgmt, 0.05):
                if self._writer:
                    self._writer.write(0, raw)
                with self._lock:
                    self._mgmt_count += 1

                tcp_payload = extract_tcp_payload(raw)
                if not tcp_payload:
                    continue
                cmds = decode_nova_mgmt(tcp_payload)
                if not cmds:
                    continue

                for cmd in cmds:
                    if cmd['direction'] != 'WRITE':
                        continue
                    ts = time.time()
                    with self._lock:
                        self._cmd_count += 1
                        before_frames = [
                            f for (t, f) in self._tile_buf
                            if ts - BEFORE_WINDOW <= t <= ts
                        ]
                    self._log_command(cmd, ts, before_frames)

    def _tile_loop(self):
        while not self._stop.is_set():
            for raw in read_bpf(self._fd_tile, self._bl_tile, 0.05):
                if self._writer:
                    self._writer.write(1, raw)
                d = decode_tile_frame(raw)
                if not d:
                    continue
                ts = time.time()
                with self._lock:
                    self._tile_count += 1
                    self._tile_buf.append((ts, d))
                    # Keep only the last 3 seconds
                    cutoff = ts - 3.0
                    self._tile_buf = [(t, f) for t, f in self._tile_buf if t >= cutoff]
                    # Log first encounter of each frame type
                    key = (d['direction'], d['etype'], d['dst'], d['src'])
                    if key not in self._tile_first_seen:
                        self._tile_first_seen[key] = d
                        self._print_new_tile(d)

    def _print_new_tile(self, d: dict):
        print(f'\n  [TILE NEW] {d["direction"]}  etype=0x{d["etype"]}  '
              f'len={d["frame_len"]}  dst={d["dst"]}  src={d["src"]}')
        print(f'             {hexdump(d["payload"])}')
        print(f'             color: {color_sniff(d["payload"])}')

    def _log_command(self, cmd: dict, ts: float, before_frames: list[dict]):
        t_str = time.strftime('%H:%M:%S', time.localtime(ts))
        print(f'\n{"═"*60}')
        print(f'  [CMD] {t_str}  {cmd["reg_name"]}  {cmd["direction"]}  '
              f'card={cmd["card"]}  → {cmd["value_str"]}')
        print(f'        raw: addr=0x{cmd["address"]:08X}  data={cmd["data_hex"]}')

        # Snapshot tile frames shortly after the command
        # We do this in a short sleep then grab from the buffer
        threading.Thread(target=self._after_snapshot,
                         args=(cmd, ts, before_frames), daemon=True).start()

    def _after_snapshot(self, cmd: dict, cmd_ts: float, before_frames: list[dict]):
        time.sleep(AFTER_WINDOW)
        with self._lock:
            after_frames = [
                f for (t, f) in self._tile_buf
                if cmd_ts < t <= cmd_ts + AFTER_WINDOW
            ]

        b_tb10 = [f for f in before_frames if f['direction'] == 'TB10→TILE']
        a_tb10 = [f for f in after_frames  if f['direction'] == 'TB10→TILE']

        print(f'  [TILE] Before: {len(b_tb10)} frames  After: {len(a_tb10)} frames  '
              f'(TB10→TILE only)')

        if b_tb10 and a_tb10:
            bsamp = b_tb10[len(b_tb10)//2]
            asamp = a_tb10[len(a_tb10)//2]
            print(f'  [TILE] Before color: {color_sniff(bsamp["payload"])}')
            print(f'  [TILE] After  color: {color_sniff(asamp["payload"])}')
            print(f'  [TILE] Diff:  {diff_payloads(bsamp["payload"], asamp["payload"])}')

            # Save reference payload if anything changed
            if asamp['payload'] != bsamp['payload']:
                label = cmd['value_str'].replace('=', '_').replace('/', '_')
                fname = f'ref_{label}.bin'
                with open(fname, 'wb') as f:
                    f.write(asamp['payload'])
                print(f'  [TILE] Saved: {fname}  ({len(asamp["payload"])} bytes)')
        elif not b_tb10:
            print('  [TILE] No tile frames in before window — is the TAP connected?')
        else:
            print('  [TILE] No tile frames after command')

    def start(self):
        threading.Thread(target=self._mgmt_loop, daemon=True).start()
        threading.Thread(target=self._tile_loop,  daemon=True).start()

    def stop(self):
        self._stop.set()

    def print_summary(self):
        with self._lock:
            print(f'\n  Management frames: {self._mgmt_count:,}')
            print(f'  Tile frames:       {self._tile_count:,}')
            print(f'  Commands decoded:  {self._cmd_count}')
            if self._tile_first_seen:
                print(f'  Unique tile frame types:')
                for (direction, etype, dst, src), d in self._tile_first_seen.items():
                    print(f'    {direction:<15} etype=0x{etype}  '
                          f'len={d["frame_len"]}  dst={dst}  src={src}')

# ── Interface listing ─────────────────────────────────────────────────────────

def list_ifaces():
    result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
    ifaces = result.stdout.strip().split()
    print('\nAvailable interfaces:')
    for iface in ifaces:
        r = subprocess.run(['ifconfig', iface], capture_output=True, text=True)
        lines = r.stdout.strip().splitlines()
        status = 'UP'   if any('UP' in l and 'flags=' in l for l in lines) else 'down'
        ether  = next((l.strip() for l in lines if 'ether '  in l), '(no MAC)')
        media  = next((l.strip() for l in lines if 'media:'  in l), '')
        print(f'  {iface:<8}  {status:<6}  {ether}  {media[:60]}')
    print()

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Novastar dual-capture: correlate Viplex commands with tile output changes')
    parser.add_argument('--list-ifaces', action='store_true',
        help='List network interfaces and exit')
    parser.add_argument('--mgmt-iface', metavar='IFACE',
        help='USB NIC on switch mirror port — sees Viplex commands (e.g. en9)')
    parser.add_argument('--tile-iface', metavar='IFACE',
        help='USB TAP monitor port — sees TB10 tile output (e.g. en10)')
    parser.add_argument('--no-pcap', action='store_true',
        help='Disable pcapng output')
    DROPBOX_CAPTURES = os.path.expanduser(
        '~/Library/CloudStorage/Dropbox-Personal/_Claude/novastar-captures')
    parser.add_argument('--out',
        default=os.path.join(DROPBOX_CAPTURES, 'session.pcapng'),
        help='Output pcapng filename (default: Dropbox-Personal/_Claude/novastar-captures/session.pcapng)')
    args = parser.parse_args()

    if args.list_ifaces:
        list_ifaces()
        return

    if not args.mgmt_iface or not args.tile_iface:
        parser.error('--mgmt-iface and --tile-iface are both required. '
                     'Use --list-ifaces to find them.')

    print(f'\n=== Novastar Dual Capture ===')
    print(f'Management (Viplex): {args.mgmt_iface}  (via switch mirror)')
    print(f'Tile output (TAP):   {args.tile_iface}')
    print(f'Waiting for Viplex commands — Ctrl+C to stop\n')
    print(f'Known registers watched:')
    for addr, name in REGISTERS.items():
        print(f'  0x{addr:08X}  {name}')
    print()

    fd_mgmt, bl_mgmt = open_bpf(args.mgmt_iface)
    fd_tile, bl_tile = open_bpf(args.tile_iface)

    writer = None if args.no_pcap else PcapngWriter(args.out, args.mgmt_iface, args.tile_iface)

    capture = DualCapture(fd_mgmt, bl_mgmt, fd_tile, bl_tile, writer)
    capture.start()

    try:
        while True:
            time.sleep(10)
            capture.print_summary()
    except KeyboardInterrupt:
        print('\n\nStopping...')

    capture.stop()
    if writer:
        writer.close()
        print(f'\n[PCAP] Saved → {args.out}')
        print(f'       Open with: wireshark {args.out}')

    capture.print_summary()
    os.close(fd_mgmt)
    os.close(fd_tile)
    print('\n[DONE]')


if __name__ == '__main__':
    main()
