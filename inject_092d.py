#!/usr/bin/env python3
"""
Inject 09:2d display config frames to drive tile without VX1000.

The 09:2d stream has two interleaved frame types:

  NULL frames:  etype=0x0000, payload=all-zeros (majority of frames)
  DATA frames:  etype = complement-pair at rotation phase N
                payload = base sequence starting at phase N+1, repeating
                (cycles through all 24 phases in steps of +1)

The 24-pair base sequence (data byte D, complement ~D):
  pos:  0  1  2   3   4  5  6  7   8  9 10   11  12 13 14   15  16 17 18   19  20 21 22 23
  val: 00 00 00  40  06 00 00 00  05 00 00   c0  03 00 00   80  02 00 00   40  01 00 00 00

Observed VX1000 behavior (V2.5.0, captured):
  - Mostly null frames at ~4/sec
  - Data frames every ~6 frames, cycling through phases 4 (0x06f9),
    12 (0x03fc), 20 (0x01fe) and zero-data phases (0x00ff)
  - Payload is IDENTICAL across all brightness levels — encodes
    tile topology/routing config, not brightness

Usage:
  sudo python3 inject_092d.py --iface en9
  sudo python3 inject_092d.py --iface en9 --rate 4 --data-every 6
  sudo python3 inject_092d.py --iface en9 --count 100
"""

import os, sys, struct, fcntl, time, argparse

# BPF ioctl constants (macOS)
BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCSHDRCMPLT = 0x80044275

# 24-element base data sequence. Each element D pairs with (~D & 0xFF).
# Non-zero values encode tile topology (192=tile height, 128=row zone, etc.)
BASE_SEQ = [
    0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x80,
    0x02, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
]

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

def comp_pair(d: int) -> bytes:
    return bytes([d & 0xFF, (~d) & 0xFF])

def dst_mac(counter: int) -> bytes:
    hi = counter & 0xFF
    return bytes([0x09, 0x2d, hi, (~hi) & 0xFF, 0x00, 0xff])

SRC_MAC = bytes(6)  # 00:00:00:00:00:00 — matches VX1000

def make_null_frame(counter: int) -> bytes:
    """Null frame: etype=0x0000, payload=zeros (majority of 09:2d stream)."""
    return dst_mac(counter) + SRC_MAC + bytes(2) + bytes(1012)

def make_data_frame(counter: int, phase: int) -> bytes:
    """
    Data frame at rotation phase N (0–23).
    etype = base_seq[N] paired with complement.
    payload = base_seq starting at N+1, wrapping, 506 pairs (1012 bytes).
    """
    etype = comp_pair(BASE_SEQ[phase])
    pairs = b''.join(
        comp_pair(BASE_SEQ[(phase + 1 + k) % 24])
        for k in range(506)
    )
    return dst_mac(counter) + SRC_MAC + etype + pairs

def main():
    parser = argparse.ArgumentParser(
        description='Inject 09:2d display config frames (full rotating sequence)')
    parser.add_argument('--iface', default='en9',
                        help='Interface (default: en9 = tile side)')
    parser.add_argument('--rate', type=float, default=4.0,
                        help='Total frames/sec (default: 4)')
    parser.add_argument('--data-every', type=int, default=6,
                        help='Send one data frame every N frames (default: 6)')
    parser.add_argument('--count', type=int, default=0,
                        help='Total frames to send (0 = run until Ctrl+C)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('ERROR: must run as root (sudo)')
        sys.exit(1)

    fd = open_bpf(args.iface)
    interval = 1.0 / args.rate
    counter = 0
    sent = 0
    phase = 0       # 0–23, advances each time a data frame is sent
    data_sent = 0

    print(f'Injecting 09:2d on {args.iface}  '
          f'rate={args.rate}/sec  data-every={args.data_every}')
    print(f'Count: {"∞" if args.count == 0 else args.count}')
    print('Ctrl+C to stop\n')

    try:
        while True:
            if sent % args.data_every == (args.data_every - 1):
                frame = make_data_frame(counter, phase)
                etype_val = BASE_SEQ[phase]
                label = f'DATA  phase={phase:2d}  etype=0x{etype_val:02x}{(~etype_val)&0xFF:02x}'
                phase = (phase + 1) % 24
                data_sent += 1
            else:
                frame = make_null_frame(counter)
                label = 'null'

            os.write(fd, frame)
            sent += 1
            counter = (counter + 7) & 0xFF

            if sent % 24 == 0:
                print(f'  {sent:5d} frames  ({data_sent} data, {sent-data_sent} null)  last: {label}')

            if args.count and sent >= args.count:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        pass

    os.close(fd)
    print(f'\nDone. Sent {sent} frames ({data_sent} data, {sent-data_sent} null).')

if __name__ == '__main__':
    main()
