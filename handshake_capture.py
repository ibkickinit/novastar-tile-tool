#!/usr/bin/env python3
"""
Novastar tile handshake capture.

Goals:
  1. Capture what TB10 sends when NO tile is connected
  2. Detect the moment a tile cable is plugged in
  3. Record every unique frame in the first 10 seconds after connect
  4. Distinguish control frames from pixel frames by ethertype
  5. Detect any TILE→TB10 response frames

Setup:
  - en9 connected to TB10 tile output port
  - Run with inline bridge if you want to see tile→TB10 too:
      sudo ifconfig bridge0 destroy
      sudo ifconfig bridge0 create
      sudo ifconfig bridge0 addm en9 addm en8
      sudo ifconfig bridge0 up
  - Or run single-sided (en9 only) for TB10 output analysis

Usage:
  sudo python3 handshake_capture.py             # en9 only, wait for tile connect
  sudo python3 handshake_capture.py --both      # en9 + en8 (bridge mode)
  sudo python3 handshake_capture.py --dump N    # dump first N unique frames fully
"""

import os, sys, struct, fcntl, time, select, threading, collections, argparse

IFACE_TB10 = 'en9'
IFACE_TILE = 'en8'

BIOCSETIF=0x8020426c; BIOCIMMEDIATE=0x80044270; BIOCGBLEN=0x40044266
BIOCSHDRCMPLT=0x80044275; BIOCPROMISC=0x20004269

def open_bpf(iface):
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCPROMISC, struct.pack('I', 1))
            buflen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, b'\x00'*4))[0]
            print(f'[BPF] /dev/bpf{i} → {iface}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError(f'No BPF for {iface}')

def read_frames(fd, buflen, timeout=0.05):
    rdy,_,_ = select.select([fd],[],[],timeout)
    if not rdy: return []
    buf = os.read(fd, buflen)
    frames=[]; off=0
    while off < len(buf):
        if off+18 > len(buf): break
        caplen,_,hdrlen = struct.unpack_from('IIH', buf, off+8)
        frames.append(buf[off+hdrlen:off+hdrlen+caplen])
        total = hdrlen+caplen; off += (total+3)&~3
    return frames

def mac(b): return ':'.join(f'{x:02x}' for x in b)

def hexdump(b, width=64):
    return ' '.join(f'{x:02x}' for x in b[:width]) + ('...' if len(b)>width else '')

def describe_frame(frame, direction='TB10→TILE'):
    if len(frame) < 14: return None
    dst = frame[0:6]
    src = frame[6:12]
    etype_bytes = frame[12:14]
    etype = etype_bytes.hex()
    payload = frame[14:]

    # In Novastar's tile protocol, the ethertype is NOT a real ethertype.
    # It's likely a frame-type / sequence field. Known real ethertypes:
    real_ethertypes = {
        '0800': 'IPv4', '0806': 'ARP', '86dd': 'IPv6',
        '8100': '802.1Q', '8899': 'Realtek-mgmt', '88cc': 'LLDP',
    }
    etype_label = real_ethertypes.get(etype, f'NOVA:0x{etype}')

    return {
        'direction': direction,
        'dst': mac(dst),
        'src': mac(src),
        'dst_raw': dst,
        'src_raw': src,
        'etype': etype,
        'etype_label': etype_label,
        'payload': payload,
        'total_len': len(frame),
        'payload_len': len(payload),
        'is_real_etype': etype in real_ethertypes,
        # First 4 bytes of payload as big-endian u32 (possible frame counter/type)
        'payload_u32': struct.unpack_from('>I', payload, 0)[0] if len(payload)>=4 else None,
        # Check for all-zero payload (idle/blank frames)
        'payload_all_zero': not any(payload),
        # Check for solid color (all bytes the same value)
        'payload_all_same': len(set(payload)) == 1 if payload else False,
        'payload_dominant': max(set(payload), key=payload.count) if payload else None,
    }


# ── Phase tracker ──────────────────────────────────────────────────────────────

class HandshakeTracker:
    """
    Watches the frame stream and detects state transitions.

    State machine:
      WAITING    → no frames or only idle frames
      ACTIVE     → steady pixel stream

    We define "transition" as a change in:
      - New ethertype appearing
      - New (dst, etype) combination
      - Frame size changing significantly
      - Direction flip (tile→tb10 frame appearing)
    """

    def __init__(self, dump_count=20):
        self.dump_count = dump_count
        self.lock = threading.Lock()

        # Per-direction tracking
        self.seen_etypes = {'TB10→TILE': collections.Counter(),
                            'TILE→TB10': collections.Counter()}
        self.seen_keys = {'TB10→TILE': {}, 'TILE→TB10': {}}  # key → first frame info
        self.frame_counts = {'TB10→TILE': 0, 'TILE→TB10': 0}
        self.dumped = 0

        # Timeline: list of (timestamp, direction, event_description)
        self.timeline = []
        self.start_time = time.time()

        # Unique frame type log — captures every new (direction, etype, len) combination
        self.unique_types = []

    def elapsed(self):
        return time.time() - self.start_time

    def ingest(self, frame, direction):
        info = describe_frame(frame, direction)
        if not info: return

        with self.lock:
            self.frame_counts[direction] += 1
            self.seen_etypes[direction][info['etype']] += 1

            # Key = (direction, etype, total_len) — identifies a frame "type"
            key = (direction, info['etype'], info['total_len'])
            is_new = key not in self.seen_keys[direction]

            if is_new:
                self.seen_keys[direction][key] = info
                self.unique_types.append((self.elapsed(), key, info))
                self._print_new_type(info, is_first=(self.dumped < self.dump_count))
                self.dumped += 1

            # Special: ANY tile→tb10 frame is immediately notable
            if direction == 'TILE→TB10' and is_new:
                self._print_tile_response(info)

    def _print_new_type(self, info, is_first=True):
        t = self.elapsed()
        print(f'\n[+{t:6.2f}s] NEW {info["direction"]}')
        print(f'          DST:   {info["dst"]}')
        print(f'          SRC:   {info["src"]}')
        print(f'          ETYPE: {info["etype_label"]}  (raw: {info["etype"]})')
        print(f'          SIZE:  {info["total_len"]}B  (payload: {info["payload_len"]}B)')

        if info['payload_all_zero']:
            print(f'          DATA:  [ALL ZERO — idle/blank frame]')
        elif info['payload_all_same']:
            print(f'          DATA:  [ALL 0x{info["payload_dominant"]:02x}]')
        else:
            print(f'          DATA:  {hexdump(info["payload"], 48)}')

        if info['payload_u32'] is not None:
            print(f'          U32_0: 0x{info["payload_u32"]:08x}  ({info["payload_u32"]})')

        # If it's a "real" ethertype, decode further
        if info['is_real_etype']:
            print(f'          [!] REAL ETHERTYPE — not a Novastar tile frame!')

        # Try to identify Novastar frame sub-type from ethertype value
        # Novastar tile ethertypes are typically small values or proprietary
        etype_int = int(info['etype'], 16)
        if etype_int < 0x0600:
            # 802.3 length field — payload length in bytes
            print(f'          [802.3] ethertype={etype_int} is a LENGTH field, not type')
        elif not info['is_real_etype']:
            print(f'          [NOVA]  Proprietary frame type 0x{info["etype"]}')

    def _print_tile_response(self, info):
        print(f'\n  ★★★ TILE→TB10 RESPONSE DETECTED! ★★★')
        print(f'  This means the tile IS communicating back to the TB10.')
        print(f'  Full payload: {hexdump(info["payload"], 128)}')

    def print_summary(self):
        print('\n\n══════════════════════════════════════════════')
        print('  HANDSHAKE CAPTURE SUMMARY')
        print('══════════════════════════════════════════════')

        for direction in ['TB10→TILE', 'TILE→TB10']:
            count = self.frame_counts[direction]
            if count == 0:
                print(f'\n  {direction}: NO FRAMES (tile is passive or not connected)')
                continue

            print(f'\n  {direction}: {count:,} total frames')
            etypes = self.seen_etypes[direction]
            print(f'  Unique ethertype values: {len(etypes)}')
            for etype, n in etypes.most_common():
                etype_int = int(etype, 16)
                # Guess frame role based on etype value
                if etype_int < 0x0600:
                    role = f'802.3-len={etype_int}'
                elif etype == '0800': role = 'IPv4'
                elif etype == '0806': role = 'ARP'
                else:
                    # Try to guess Novastar frame type
                    hi = (etype_int >> 8) & 0xFF
                    lo = etype_int & 0xFF
                    role = f'NOVA hi=0x{hi:02x} lo=0x{lo:02x}'
                print(f'    0x{etype}  {n:8,}×  [{role}]')

        print(f'\n  Unique frame types seen (in order):')
        print(f'  {"Time":>8}  {"Direction":<12} {"Etype":<8} {"Size":>6}  Notes')
        print(f'  {"-"*70}')
        for t, (direction, etype, total_len), info in self.unique_types:
            note = ''
            if info['payload_all_zero']: note = 'ALL-ZERO'
            elif info['is_real_etype']: note = '← REAL ETHERTYPE'
            elif info['direction'] == 'TILE→TB10': note = '← TILE RESPONSE!'
            etype_int = int(etype, 16)
            print(f'  {t:8.3f}s  {direction:<12} 0x{etype}  {total_len:6}B  {note}')

        print()
        print('  INTERPRETATION:')
        if not any(self.frame_counts[d] > 0 for d in ['TILE→TB10']):
            print('  → Tile sends NOTHING back. TB10 resolution config is pre-loaded.')
            print('  → Protocol is entirely one-way (broadcast pixel stream).')
            print('  → To drive a tile directly: just send the right pixel frames — no handshake needed.')
        else:
            print('  → Tile DOES respond. Capture the response frames above for protocol decode.')

        n_nova_etypes = len([e for e in self.seen_etypes['TB10→TILE']
                             if e not in ('0800','0806','86dd','8100','8899','88cc')])
        if n_nova_etypes > 1:
            print(f'  → {n_nova_etypes} distinct Novastar ethertype values found.')
            print(f'  → These likely distinguish: pixel frames / control frames / sync frames.')
            print(f'  → Compare the byte content of each type to identify their roles.')


# ── Main ───────────────────────────────────────────────────────────────────────

stop_event = threading.Event()

def capture_loop(fd, buflen, direction, tracker):
    while not stop_event.is_set():
        for frame in read_frames(fd, buflen, 0.05):
            tracker.ingest(frame, direction)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--both', action='store_true',
        help='Capture both directions (requires bridge0 setup)')
    parser.add_argument('--dump', type=int, default=30,
        help='Number of unique frame types to dump fully (default: 30)')
    parser.add_argument('--duration', type=float, default=30.0,
        help='Total capture duration in seconds (default: 30)')
    parser.add_argument('--iface-tb10', default=IFACE_TB10)
    parser.add_argument('--iface-tile', default=IFACE_TILE)
    args = parser.parse_args()

    print(f'\n=== Novastar Tile Handshake Capture ===')
    print(f'Duration: {args.duration}s')
    if args.both:
        print(f'Mode: INLINE (both directions via bridge0)')
        print(f'  TB10 output: {args.iface_tb10}')
        print(f'  Tile side:   {args.iface_tile}')
    else:
        print(f'Mode: SINGLE-SIDED (TB10 output on {args.iface_tb10} only)')
    print()
    print('TIP: Plug/unplug the tile cable AFTER this starts to capture the handshake.')
    print('     Watch for [+Xs] NEW events — those mark protocol state changes.')
    print()

    tracker = HandshakeTracker(dump_count=args.dump)

    fd_tb10, bl_tb10 = open_bpf(args.iface_tb10)

    threads = [
        threading.Thread(target=capture_loop, args=(fd_tb10, bl_tb10, 'TB10→TILE', tracker), daemon=True),
    ]

    if args.both:
        fd_tile, bl_tile = open_bpf(args.iface_tile)
        threads.append(
            threading.Thread(target=capture_loop, args=(fd_tile, bl_tile, 'TILE→TB10', tracker), daemon=True)
        )

    for t in threads: t.start()

    try:
        deadline = time.time() + args.duration
        while time.time() < deadline and not stop_event.is_set():
            remaining = deadline - time.time()
            tb10_count = tracker.frame_counts['TB10→TILE']
            tile_count = tracker.frame_counts['TILE→TB10']
            print(f'\r  [{remaining:5.1f}s left]  TB10→TILE: {tb10_count:,}  TILE→TB10: {tile_count:,}  '
                  f'Unique types: {len(tracker.unique_types)}   ', end='', flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\nStopped by user')

    stop_event.set()
    tracker.print_summary()

    os.close(fd_tb10)
    if args.both:
        os.close(fd_tile)
    print('[DONE]')


if __name__ == '__main__':
    main()
