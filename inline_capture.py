#!/usr/bin/env python3
"""
In-line capture between TB10 tile output (en9) and LED tile (en8).
Mac is bridged transparently — tile works normally, we see everything.

Run AFTER:
  sudo ifconfig bridge0 create
  sudo ifconfig bridge0 addm en9 addm en8
  sudo ifconfig bridge0 up
"""

import os, sys, struct, fcntl, time, select, threading, collections

IFACE_TB10 = 'en9'   # TB10 tile output side
IFACE_TILE = 'en8'   # LED tile side

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
            print(f'[BPF] {iface} → /dev/bpf{i}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError(f'No BPF for {iface}')

def read_frames(fd, buflen, timeout=0.1):
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
def hexdump(b, width=32): return ' '.join(f'{x:02x}' for x in b[:width]) + ('...' if len(b)>width else '')

# Known MACs / ethertype labels
NOVA_TILE_DST = bytes.fromhex('098700000000')
ETYPES = {
    '0800': 'IPv4', '0806': 'ARP', '86dd': 'IPv6',
    '8100': '802.1Q', '8899': 'Realtek-mgmt', '88cc': 'LLDP',
}

lock = threading.Lock()
stats = {'tb10_frames':0, 'tile_frames':0, 'tb10_bytes':0, 'tile_bytes':0}
seen_types = collections.Counter()   # (direction, etype) → count
first_seen = {}                      # (direction, etype, dst, src) → frame bytes

def classify(frame, direction):
    if len(frame) < 14:
        return
    dst = frame[0:6]; src = frame[6:12]
    etype = frame[12:14].hex()
    payload = frame[14:]
    key = (direction, etype, dst.hex(), src.hex())

    with lock:
        if direction == 'TB10→TILE':
            stats['tb10_frames'] += 1
            stats['tb10_bytes'] += len(frame)
        else:
            stats['tile_frames'] += 1
            stats['tile_bytes'] += len(frame)

        seen_types[(direction, etype)] += 1

        if key not in first_seen:
            first_seen[key] = frame
            # Print immediately on first encounter
            label = ETYPES.get(etype, f'0x{etype}')
            nova = ' *** NOVASTAR ***' if dst == NOVA_TILE_DST else ''
            print(f'\n[NEW] {direction}')
            print(f'      DST:   {mac(dst)}{nova}')
            print(f'      SRC:   {mac(src)}')
            print(f'      TYPE:  {label}')
            print(f'      LEN:   {len(frame)} bytes')
            print(f'      DATA:  {hexdump(payload, 48)}')

            # Extra decode for ARP
            if etype == '0806' and len(payload) >= 28:
                import socket as _s
                op = struct.unpack_from('!H', payload, 6)[0]
                sha = payload[8:14]; spa = payload[14:18]
                tha = payload[18:24]; tpa = payload[24:28]
                print(f'      ARP:   {"Request" if op==1 else "Reply"} '
                      f'{mac(sha)} ({_s.inet_ntoa(spa)}) → '
                      f'{mac(tha)} ({_s.inet_ntoa(tpa)})')

            # Extra decode for IPv4
            if etype == '0800' and len(payload) >= 20:
                import socket as _s
                proto = payload[9]
                sip = _s.inet_ntoa(payload[12:16])
                dip = _s.inet_ntoa(payload[16:20])
                protos = {6:'TCP', 17:'UDP', 1:'ICMP'}
                print(f'      IP:    {sip} → {dip} proto={protos.get(proto,proto)}')
                if proto in (6,17) and len(payload) >= 24:
                    sport = struct.unpack_from('!H', payload, 20)[0]
                    dport = struct.unpack_from('!H', payload, 22)[0]
                    print(f'      PORTS: {sport} → {dport}')

def capture_loop(fd, buflen, direction):
    while not stop_event.is_set():
        for frame in read_frames(fd, buflen, 0.05):
            classify(frame, direction)

stop_event = threading.Event()

def print_stats():
    while not stop_event.is_set():
        time.sleep(5)
        with lock:
            print(f'\n  ── Stats ── '
                  f'TB10→TILE: {stats["tb10_frames"]:,} frames ({stats["tb10_bytes"]//1024}KB)  '
                  f'TILE→TB10: {stats["tile_frames"]:,} frames ({stats["tile_bytes"]//1024}KB)')
            for (direction, etype), count in sorted(seen_types.items()):
                label = ETYPES.get(etype, f'0x{etype}')
                print(f'           {direction} {label}: {count:,}')

def main():
    print(f'\n=== Novastar In-Line Capture ===')
    print(f'TB10 side: {IFACE_TB10}  |  Tile side: {IFACE_TILE}')
    print(f'Bridge must be up: bridge0 = {IFACE_TB10} + {IFACE_TILE}')
    print(f'Ctrl+C to stop\n')

    fd_tb10, bl_tb10 = open_bpf(IFACE_TB10)
    fd_tile, bl_tile = open_bpf(IFACE_TILE)

    threads = [
        threading.Thread(target=capture_loop, args=(fd_tb10, bl_tb10, 'TB10→TILE'), daemon=True),
        threading.Thread(target=capture_loop, args=(fd_tile, bl_tile, 'TILE→TB10'), daemon=True),
        threading.Thread(target=print_stats, daemon=True),
    ]
    for t in threads: t.start()

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print('\n\nStopping...')
        stop_event.set()

    os.close(fd_tb10)
    os.close(fd_tile)

    print('\n=== FINAL SUMMARY ===')
    with lock:
        for (direction, etype), count in sorted(seen_types.items()):
            label = ETYPES.get(etype, f'0x{etype}')
            print(f'  {direction:<15} {label:<20} {count:,} frames')

        print('\nAll unique frame types seen:')
        for key, frame in first_seen.items():
            direction, etype, dst_hex, src_hex = key
            label = ETYPES.get(etype, f'0x{etype}')
            print(f'  {direction} | {label} | dst={dst_hex} | src={src_hex}')
            print(f'    first frame: {hexdump(frame[14:], 32)}')

if __name__ == '__main__':
    main()
