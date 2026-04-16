#!/usr/bin/env python3
"""
Inject pixel data (09:1e frames) to drive a tile without a VX1000.

Frame format (575 bytes each):
  dst[0:2] = 09:1e  — Novastar pixel frame prefix
  dst[2:6] = first 4 hardware pixel columns (R,G,B,R of pixel 0)
  src[0:6] = pixels 1–2 (6 bytes = 2 RGB pixels)
  etype    = pixel 3 high/low bytes (2 bytes)
  payload  = pixels 4–190, remaining 187 active pixel columns (561 bytes)

In practice: build as bytes([0x09, 0x1e]) + bytes([r, g, b] * 191)
The first 12 bytes naturally land in DST/SRC/ETYPE fields; the rest in payload.
Total: 2 + 573 = 575 bytes.

Sync frame: same format but all-zero RGB — bytes([0x09, 0x1e]) + bytes(573)
1 display frame = 192 pixel rows, preceded by a few sync frames.

Run alongside inject_092d.py for fully VX1000-independent tile operation:
  Terminal 1: sudo python3 inject_092d.py --iface en9
  Terminal 2: sudo python3 inject_pattern.py --iface en9 --color white

Usage:
  sudo python3 inject_pattern.py --iface en9 --color white
  sudo python3 inject_pattern.py --iface en9 --color red --fps 4
  sudo python3 inject_pattern.py --iface en9 --r 191 --g 0 --b 0
  sudo python3 inject_pattern.py --iface en9 --color black --fps 1
"""

import os, sys, struct, fcntl, time, argparse

# BPF ioctl constants (macOS)
BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275

ROWS = 192      # physical rows per frame
COLS = 191      # total columns in stream (4 HW + 187 active)

NAMED_COLORS = {
    'white': (0xbf, 0xbf, 0xbf),
    'red':   (0xbf, 0x00, 0x00),
    'green': (0x00, 0xbf, 0x00),
    'blue':  (0x00, 0x00, 0xbf),
    'black': (0x00, 0x00, 0x00),
}

def open_bpf(iface: str):
    for i in range(256):
        dev = f'/dev/bpf{i}'
        try:
            fd = os.open(dev, os.O_RDWR)
        except OSError:
            continue
        ifr = iface.encode()[:15].ljust(16, b'\x00')
        fcntl.ioctl(fd, BIOCSETIF, ifr)
        fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
        return fd
    raise RuntimeError('No BPF device available')

def build_row_frame(r: int, g: int, b: int) -> bytes:
    """575-byte pixel row: [09, 1e] + 191 × [r, g, b]"""
    return bytes([0x09, 0x1e]) + bytes([r, g, b] * COLS)

def build_sync_frame() -> bytes:
    """575-byte sync/blank row: [09, 1e] + 573 zeros"""
    return bytes([0x09, 0x1e]) + bytes(573)

def main():
    parser = argparse.ArgumentParser(
        description='Inject 09:1e pixel frames to drive tile without VX1000')
    parser.add_argument('--iface', default='en9',
                        help='Interface to inject on (default: en9)')
    parser.add_argument('--fps', type=float, default=4.0,
                        help='Complete display frames per second (default: 4)')
    parser.add_argument('--color', default='white',
                        choices=list(NAMED_COLORS.keys()),
                        help='Named color (default: white)')
    parser.add_argument('--r', type=int, default=None, metavar='R',
                        help='Red component 0-255 (overrides --color)')
    parser.add_argument('--g', type=int, default=None, metavar='G',
                        help='Green component 0-255 (overrides --color)')
    parser.add_argument('--b', type=int, default=None, metavar='B',
                        help='Blue component 0-255 (overrides --color)')
    parser.add_argument('--sync-frames', type=int, default=3,
                        help='Sync frames to send before each display frame (default: 3)')
    parser.add_argument('--tight', action='store_true',
                        help='No sleep between display frames — send continuously at BPF max rate')
    parser.add_argument('--count', type=int, default=0,
                        help='Display frames to send (0 = run until Ctrl+C)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('ERROR: must run as root (sudo)')
        sys.exit(1)

    # Resolve color
    if args.r is not None or args.g is not None or args.b is not None:
        r = args.r if args.r is not None else 0
        g = args.g if args.g is not None else 0
        b = args.b if args.b is not None else 0
    else:
        r, g, b = NAMED_COLORS[args.color]

    color_desc = f'rgb({r:#04x}, {g:#04x}, {b:#04x})'

    # Pre-build frame buffers
    sync_frame = build_sync_frame()
    row_frame  = build_row_frame(r, g, b)

    fd = open_bpf(args.iface)
    frame_interval = 1.0 / args.fps
    frames_sent = 0

    rate_desc = 'continuous (tight)' if args.tight else f'{args.fps}/sec'
    print(f'Injecting pixel frames on {args.iface}')
    print(f'Color: {args.color if args.r is None else "custom"} {color_desc}')
    print(f'Rate: {rate_desc}  '
          f'({args.sync_frames} sync + {ROWS} row frames per display frame)')
    print(f'Count: {"∞" if args.count == 0 else args.count}')
    print('Run inject_092d.py simultaneously for full VX1000-independent control.')
    print('Ctrl+C to stop\n')

    try:
        while True:
            t0 = time.monotonic()

            # Sync frames
            for _ in range(args.sync_frames):
                os.write(fd, sync_frame)

            # 192 pixel rows
            for _ in range(ROWS):
                os.write(fd, row_frame)

            frames_sent += 1

            if frames_sent % 10 == 0:
                print(f'  {frames_sent:5d} display frames sent')

            if args.count and frames_sent >= args.count:
                break

            if not args.tight:
                elapsed = time.monotonic() - t0
                remaining = frame_interval - elapsed
                if remaining > 0:
                    time.sleep(remaining)

    except KeyboardInterrupt:
        pass

    os.close(fd)
    total_writes = frames_sent * (args.sync_frames + ROWS)
    print(f'\nDone. Sent {frames_sent} display frames ({total_writes} total BPF writes).')

if __name__ == '__main__':
    main()
