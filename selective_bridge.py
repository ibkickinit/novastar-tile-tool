#!/usr/bin/env python3
"""
selective_bridge.py — Software Ethernet bridge with optional frame filtering.

Replaces macOS bridge0 with a transparent Python forwarder between en11 and en9.
Lets you selectively DROP certain frame types and observe whether brightness
control still works — tells us exactly which frame type carries brightness.

SETUP (run as root):
  1. Tear down the hardware bridge:
       sudo ifconfig bridge0 destroy

  2. Start this script (pick a test mode):
       sudo python3 selective_bridge.py --iface-a en11 --iface-b en9
         --drop 092d          # drop all 09:2d frames → does brightness break?
         --drop 093c          # drop all 09:3c frames → does brightness break?
         --drop sync          # drop 09:1e:00:00:00:00 frames → does brightness break?
         --drop-nothing       # full transparent forward (baseline, should work)

  3. Watch the tile. Change brightness on VX1000. Does it still work?

  4. Restore the bridge when done:
       sudo ifconfig bridge0 create
       sudo ifconfig bridge0 addm en11 addm en9
       sudo ifconfig bridge0 up

Examples:
  # Baseline: full transparent forward
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop-nothing

  # Drop 09:2d — does brightness still work?
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop 092d

  # Drop 09:3c — does brightness still work?
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop 093c

  # Drop all sync (09:1e:00) — does brightness still work?
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop sync

  # Drop ALL control (09:2d AND 09:3c) at once
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --drop 092d --drop 093c

  # Pass ONLY pixel frames (drop everything except 09:1e pixel)
  sudo python3 selective_bridge.py --iface-a en11 --iface-b en9 --pass-only pixel
"""

import os, sys, struct, fcntl, select, time, argparse, threading, collections

BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSHDRCMPLT = 0x80044275
BIOCPROMISC   = 0x20004269
BIOCSBLEN     = 0xc0044267

def open_bpf(iface, buflen_request=524288):
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            try:
                fcntl.ioctl(fd, BIOCSBLEN, struct.pack('I', buflen_request))
            except Exception:
                pass
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCPROMISC, struct.pack('I', 1))
            buflen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, b'\x00'*4))[0]
            print(f'[BPF] /dev/bpf{i} → {iface}  buflen={buflen:,}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError(f'No BPF device for {iface}')

def read_bpf(fd, buflen, timeout=0.005):
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

def write_bpf(fd, frame):
    os.write(fd, bytes(frame))

def should_drop(frame, drop_set, pass_only):
    """Return True if this frame should be dropped based on filter settings."""
    if len(frame) < 6:
        return False

    dst = frame[0:2].hex()
    is_pixel = (frame[0:2] == b'\x09\x1e' and frame[2] != 0)
    is_sync  = (frame[0:2] == b'\x09\x1e' and frame[2] == 0)
    is_092d  = (frame[0:2] == b'\x09\x2d')
    is_093c  = (frame[0:2] == b'\x09\x3c')

    if pass_only:
        # Only pass specified types, drop everything else
        if pass_only == 'pixel' and is_pixel:
            return False
        if pass_only == 'sync'  and is_sync:
            return False
        if pass_only == '092d'  and is_092d:
            return False
        if pass_only == '093c'  and is_093c:
            return False
        if pass_only == 'nova'  and (is_pixel or is_sync or is_092d or is_093c):
            return False
        return True  # drop everything not in pass_only

    # Drop-based filtering
    if 'sync'  in drop_set and is_sync:
        return True
    if '092d'  in drop_set and is_092d:
        return True
    if '093c'  in drop_set and is_093c:
        return True
    if 'pixel' in drop_set and is_pixel:
        return True

    return False

class SoftBridge:
    def __init__(self, fd_a, bl_a, fd_b, bl_b, drop_set, pass_only):
        self.fd_a = fd_a;  self.bl_a = bl_a
        self.fd_b = fd_b;  self.bl_b = bl_b
        self.drop_set = drop_set
        self.pass_only = pass_only
        self._stop = threading.Event()
        self._lock = threading.Lock()

        # Stats
        self.stats = {
            'a_rx': 0, 'a_tx': 0, 'a_drop': 0,
            'b_rx': 0, 'b_tx': 0, 'b_drop': 0,
        }
        self.drop_type_counts = collections.Counter()

    def _forward(self, src_fd, src_bl, dst_fd, direction):
        for frame in read_bpf(src_fd, src_bl, timeout=0.002):
            with self._lock:
                self.stats[f'{direction}_rx'] += 1

            drop = should_drop(frame, self.drop_set, self.pass_only)

            if drop:
                ftype = frame[0:2].hex() if len(frame) >= 2 else 'short'
                with self._lock:
                    self.stats[f'{direction}_drop'] += 1
                    self.drop_type_counts[ftype] += 1
            else:
                try:
                    write_bpf(dst_fd, frame)
                    with self._lock:
                        self.stats[f'{direction}_tx'] += 1
                except OSError:
                    pass

    def _loop_a_to_b(self):
        while not self._stop.is_set():
            self._forward(self.fd_a, self.bl_a, self.fd_b, 'a')

    def _loop_b_to_a(self):
        while not self._stop.is_set():
            self._forward(self.fd_b, self.bl_b, self.fd_a, 'b')

    def start(self):
        threading.Thread(target=self._loop_a_to_b, daemon=True).start()
        threading.Thread(target=self._loop_b_to_a, daemon=True).start()

    def stop(self):
        self._stop.set()

    def print_stats(self):
        with self._lock:
            s = self.stats.copy()
            dtc = dict(self.drop_type_counts)
        print(f'\n  A→B: rx={s["a_rx"]:,}  tx={s["a_tx"]:,}  drop={s["a_drop"]:,}')
        print(f'  B→A: rx={s["b_rx"]:,}  tx={s["b_tx"]:,}  drop={s["b_drop"]:,}')
        if dtc:
            print(f'  Dropped by type: {dtc}')


def main():
    parser = argparse.ArgumentParser(description='Selective software Ethernet bridge')
    parser.add_argument('--iface-a', default='en11', help='VX1000-side interface (default: en11)')
    parser.add_argument('--iface-b', default='en9',  help='Tile-side interface (default: en9)')
    parser.add_argument('--drop', action='append', default=[],
                        metavar='TYPE',
                        help='Frame type to drop: 092d, 093c, sync, pixel. '
                             'Can specify multiple times.')
    parser.add_argument('--pass-only', default=None,
                        metavar='TYPE',
                        help='Pass ONLY this type, drop everything else: '
                             'pixel, sync, 092d, 093c, nova (all Novastar)')
    parser.add_argument('--drop-nothing', action='store_true',
                        help='Fully transparent bridge (baseline test)')
    args = parser.parse_args()

    if args.drop_nothing:
        args.drop = []
        args.pass_only = None

    print(f'\n=== Selective Software Bridge ===')
    print(f'A: {args.iface_a}  (VX1000 side)')
    print(f'B: {args.iface_b}  (Tile side)')
    if args.pass_only:
        print(f'Mode: PASS ONLY → {args.pass_only}  (everything else DROPPED)')
    elif args.drop:
        print(f'Mode: Drop → {args.drop}')
    else:
        print(f'Mode: FULLY TRANSPARENT (drop nothing)')
    print()
    print('Make sure bridge0 is destroyed first:')
    print('  sudo ifconfig bridge0 destroy')
    print()

    fd_a, bl_a = open_bpf(args.iface_a)
    fd_b, bl_b = open_bpf(args.iface_b)

    bridge = SoftBridge(fd_a, bl_a, fd_b, bl_b, set(args.drop), args.pass_only)
    bridge.start()

    print('Bridge running — change brightness on VX1000 and observe tile.')
    print('Stats print every 5s. Ctrl+C to stop.\n')

    try:
        while True:
            time.sleep(5)
            bridge.print_stats()
    except KeyboardInterrupt:
        print('\nStopping...')

    bridge.stop()
    bridge.print_stats()
    os.close(fd_a)
    os.close(fd_b)
    print('\n[DONE]  Restore bridge with:')
    print('  sudo ifconfig bridge0 create && sudo ifconfig bridge0 addm en11 addm en9 && sudo ifconfig bridge0 up')

if __name__ == '__main__':
    main()
