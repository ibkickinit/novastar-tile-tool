#!/usr/bin/env python3
"""
inject_brightness.py — Set LED tile brightness by injecting 09:3c frames.

The VX1000 encodes brightness in 09:3c Ethernet frames sent to the tile.
payload[0] = brightness (0x00–0xFF = 0–100%).
This script constructs and injects those frames directly from the Mac,
bypassing the VX1000 for brightness control.

SETUP:
  - bridge0 must be up (or use --iface en9 to inject directly to tile side)
  - Run as root (BPF write requires root)

Usage:
  sudo python3 inject_brightness.py --level 50           # 50% brightness
  sudo python3 inject_brightness.py --level 0            # 0% (off)
  sudo python3 inject_brightness.py --level 100          # full brightness
  sudo python3 inject_brightness.py --sweep 0 100 5      # sweep 0→100% in 5s
  sudo python3 inject_brightness.py --sweep 100 0 3      # sweep 100→0% in 3s

Options:
  --iface IFACE   Interface to inject on (default: en9, tile side)
  --level N       Set brightness to N% (0–100) and hold
  --count N       How many frames to send per set command (default: 10)
  --sweep A B T   Sweep from A% to B% over T seconds
"""

import os, sys, struct, fcntl, time, argparse

BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275

def open_bpf_write(iface):
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            print(f'[BPF] /dev/bpf{i} → {iface}')
            return fd
        except OSError:
            continue
    raise RuntimeError(f'No BPF device available for {iface}')

def make_brightness_frame(level_pct: float) -> bytes:
    """
    Build a 09:3c brightness frame.
    level_pct: 0.0–100.0
    Returns full Ethernet frame bytes.
    """
    b = max(0, min(255, round(level_pct * 255 / 100)))
    chk   = (b + 3) & 0xFF
    carry = 0x04 if b >= 0xFD else 0x03
    payload = bytes([b, chk, carry, 0x67, 0x04]) + b'\x00' * 1003

    dst   = bytes([0x09, 0x3c, 0x01, 0xff, 0xff, 0xff])
    src   = bytes([0x01, 0x00, 0x01, 0x00, 0x00, 0x02])
    etype = bytes([0x01, 0x00])
    return dst + src + etype + payload

def send_brightness(fd, level_pct: float, count: int = 10, interval: float = 0.06):
    """Send brightness command 'count' times, spaced 'interval' seconds apart."""
    frame = make_brightness_frame(level_pct)
    b = max(0, min(255, round(level_pct * 255 / 100)))
    print(f'  Sending {count}× brightness={level_pct:.1f}%  (byte=0x{b:02x}={b})')
    for _ in range(count):
        os.write(fd, frame)
        time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description='VX1000 brightness injector')
    parser.add_argument('--iface', default='en9',
                        help='Inject on this interface (default: en9, tile side)')
    parser.add_argument('--level', type=float, default=None,
                        help='Set brightness to this percent (0–100) and hold')
    parser.add_argument('--count', type=int, default=10,
                        help='Frames to send per set command (default: 10)')
    parser.add_argument('--sweep', nargs=3, type=float,
                        metavar=('FROM', 'TO', 'SECS'),
                        help='Sweep from FROM%% to TO%% over SECS seconds')
    args = parser.parse_args()

    if args.level is None and args.sweep is None:
        parser.print_help()
        sys.exit(1)

    fd = open_bpf_write(args.iface)

    try:
        if args.level is not None:
            send_brightness(fd, args.level, count=args.count)
            print('Done.')

        if args.sweep is not None:
            from_pct, to_pct, secs = args.sweep
            # 17fps is the VX1000's rate; match it
            fps = 17
            steps = max(2, int(secs * fps))
            interval = secs / steps
            print(f'Sweeping {from_pct:.0f}%→{to_pct:.0f}% over {secs:.1f}s  ({steps} steps @ {fps}fps)')
            for i in range(steps + 1):
                level = from_pct + (to_pct - from_pct) * i / steps
                frame = make_brightness_frame(level)
                os.write(fd, frame)
                b = max(0, min(255, round(level * 255 / 100)))
                print(f'  {i:>4}/{steps}  {level:>6.1f}%  byte=0x{b:02x}')
                if i < steps:
                    time.sleep(interval)
            print('Sweep done.')

    finally:
        os.close(fd)

if __name__ == '__main__':
    main()
