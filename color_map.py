#!/usr/bin/env python3
"""
VX1000 color/brightness mapping tool.

Samples the tile pixel stream every 0.5 seconds and prints the current
pixel value and dst MAC. Run while stepping through test patterns on the
VX1000 to build a brightness/color map.

Usage:
    sudo python3 color_map.py --iface en9
"""

import os, sys, struct, fcntl, select, time, argparse, collections

NOVA_PREFIX = b'\x09'   # all Novastar frames start with 0x09

BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSHDRCMPLT = 0x80044275
BIOCPROMISC   = 0x20004269

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
    raise RuntimeError(f'No BPF device for {iface}')

def read_frames(fd, buflen, timeout=0.1):
    rdy, _, _ = select.select([fd], [], [], timeout)
    if not rdy:
        return []
    buf = os.read(fd, buflen)
    frames, off = [], 0
    while off < len(buf):
        if off + 18 > len(buf):
            break
        caplen, _, hdrlen = struct.unpack_from('IIH', buf, off + 8)
        frames.append(buf[off + hdrlen: off + hdrlen + caplen])
        total = hdrlen + caplen
        off += (total + 3) & ~3
    return frames

def analyze_payload(payload):
    if not payload:
        return '(empty)'
    # Count unique bytes in first 96 bytes
    sample = payload[:96]
    freq = collections.Counter(sample)
    top = freq.most_common(3)
    if len(top) == 1:
        v = top[0][0]
        return f'SOLID  0x{v:02X} ({v},{v},{v})  brightness≈{v/255*100:.0f}%'
    # Check if RGB triplets are uniform
    if len(payload) >= 6:
        r, g, b = payload[0], payload[1], payload[2]
        triplets = [(payload[i], payload[i+1], payload[i+2])
                    for i in range(0, min(len(payload)-2, 96), 3)]
        unique = set(triplets)
        if len(unique) == 1:
            return f'SOLID  RGB=({r},{g},{b})  hex=({r:02X},{g:02X},{b:02X})'
    return f'MIXED  top bytes: {[(hex(k),v) for k,v in top]}'

def mac_str(b):
    return ':'.join(f'{x:02x}' for x in b)

def main():
    parser = argparse.ArgumentParser(description='VX1000 color/brightness map tool')
    parser.add_argument('--iface', default='en9', help='Tile-side interface (default: en9)')
    parser.add_argument('--interval', type=float, default=0.5,
                        help='Sample interval in seconds (default: 0.5)')
    parser.add_argument('--brightness', action='store_true',
                        help='Brightness-ratio mode: show pixel vs blank frame ratio live')
    args = parser.parse_args()

    fd, buflen = open_bpf(args.iface)

    if args.brightness:
        print(f'Brightness-ratio mode — watch ratio shift as you change brightness')
        print(f'Sampling every {args.interval}s on {args.iface} — Ctrl+C to stop\n')
        print(f'  {"Time":<10} {"pixel":>7} {"blank":>7} {"other":>7}  {"pixel%":>7}  {"blank%":>7}  note')
        print(f'  {"─"*10} {"─"*7} {"─"*7} {"─"*7}  {"─"*7}  {"─"*7}  {"─"*20}')
        pixel_count = 0
        blank_count = 0
        other_count = 0
        next_sample = time.time()
        try:
            while True:
                for frame in read_frames(fd, buflen, timeout=0.05):
                    if len(frame) < 14:
                        continue
                    if frame[0:2] != b'\x09\x1e':
                        other_count += 1
                        continue
                    if frame[2] == 0:
                        blank_count += 1
                    else:
                        pixel_count += 1
                now = time.time()
                if now >= next_sample:
                    next_sample = now + args.interval
                    t = time.strftime('%H:%M:%S')
                    total = pixel_count + blank_count + other_count
                    pp = pixel_count / total * 100 if total else 0
                    bp = blank_count / total * 100 if total else 0
                    note = ''
                    if bp > 80:   note = '<<< near 0% brightness?'
                    elif bp < 2:  note = '>>> near 100% brightness?'
                    elif pp > 95: note = 'high pixel ratio'
                    print(f'  {t:<10} {pixel_count:>7} {blank_count:>7} {other_count:>7}  '
                          f'{pp:>6.1f}%  {bp:>6.1f}%  {note}')
                    pixel_count = blank_count = other_count = 0
        except KeyboardInterrupt:
            print('\n[DONE]')
        finally:
            os.close(fd)
        return

    print(f'Sampling every {args.interval}s — change patterns on VX1000, Ctrl+C to stop\n')
    print(f'  {"Time":<10} {"Dst MAC":<22} {"Ethertype":<12} {"Payload analysis"}')
    print(f'  {"─"*10} {"─"*22} {"─"*12} {"─"*40}')

    # Track all distinct frame types seen since last sample
    # key = (dst_mac_hex, etype_hex), value = (count, last_payload)
    seen_since_sample = {}
    next_sample = time.time()
    first_sample = True

    try:
        while True:
            for frame in read_frames(fd, buflen, timeout=0.05):
                if len(frame) < 14:
                    continue
                dst = frame[0:6]
                # Only care about Novastar frames (dst starts with 0x09)
                if dst[0:1] != b'\x09':
                    continue
                key = (dst.hex(), frame[12:14].hex())
                payload = frame[14:]
                if key in seen_since_sample:
                    seen_since_sample[key] = (seen_since_sample[key][0] + 1, payload)
                else:
                    seen_since_sample[key] = (1, payload)

            now = time.time()
            if now >= next_sample:
                next_sample = now + args.interval
                t = time.strftime('%H:%M:%S')

                if not seen_since_sample:
                    print(f'  {t:<10} (no frames)')
                else:
                    # Separate pixel-stream frames from low-frequency control frames
                    total = sum(c for c, _ in seen_since_sample.values())
                    for (dst_hex, etype_hex), (count, payload) in sorted(
                            seen_since_sample.items(), key=lambda x: -x[1][0]):
                        dst_s = ':'.join(dst_hex[i:i+2] for i in range(0, 12, 2))
                        etype_s = f'0x{etype_hex}'
                        pct = count / total * 100
                        flag = '  *** CONTROL' if pct < 5.0 else ''
                        analysis = analyze_payload(payload)
                        print(f'  {t:<10} {dst_s:<22} 0x{etype_hex:<10} '
                              f'{count:>6}frm ({pct:4.1f}%)  {analysis}{flag}')
                    print()

                seen_since_sample = {}

    except KeyboardInterrupt:
        print('\n[DONE]')
    finally:
        os.close(fd)

if __name__ == '__main__':
    main()
