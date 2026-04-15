#!/usr/bin/env python3
"""
Novastar tile protocol decoder — fires test commands and captures reference frames.

Setup:
  1. Bridge: sudo ifconfig bridge0 create && sudo ifconfig bridge0 addm en9 addm en8 && sudo ifconfig bridge0 up
  2. TB10 management port reachable at 192.168.0.10 (switch port 3/4)
  3. en9 = TB10 tile output, en8 = LED tile side

Run modes:
  python3 decode_capture.py --scan          # auto-cycle colors, save reference frames
  python3 decode_capture.py --color red     # capture during single test mode
  python3 decode_capture.py --passive       # just watch frames
"""

import os, sys, struct, fcntl, time, select, socket, threading, collections, argparse

IFACE_TB10 = 'en9'
IFACE_TILE = 'en8'
MGMT_IP    = '192.168.0.10'
MGMT_PORT  = 5200

BIOCSETIF=0x8020426c; BIOCIMMEDIATE=0x80044270; BIOCGBLEN=0x40044266
BIOCSHDRCMPLT=0x80044275; BIOCPROMISC=0x20004269

TEST_MODES = {'off':0,'red':2,'green':3,'blue':4,'white':5,'grid':6}

# ── BPF ───────────────────────────────────────────────────────────────────────

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

# ── Novastar command ───────────────────────────────────────────────────────────

def send_test_mode(mode_name):
    mode_val = TEST_MODES.get(mode_name.lower())
    if mode_val is None:
        print(f'[CMD] Unknown mode: {mode_name}'); return False
    hdr = bytes([0x55,0xAA,0x00,0x00,0xFE,0xFF,0x01,0xFF])
    hdr += struct.pack('<HBB', 0xFFFF, 0x01, 0x00)
    hdr += struct.pack('<IH', 0x02000101, 1)
    content = hdr[2:] + bytes([mode_val])
    c = (sum(content) + 0x5555) & 0xFFFF
    pkt = hdr + bytes([mode_val]) + struct.pack('<H', c)
    try:
        s = socket.create_connection((MGMT_IP, MGMT_PORT), timeout=3)
        s.sendall(pkt)
        time.sleep(0.2)
        try: resp = s.recv(256); print(f'[CMD] set_{mode_name} ACK: {resp.hex()}')
        except: print(f'[CMD] set_{mode_name}={mode_val} sent (no ACK)')
        s.close(); return True
    except Exception as e:
        print(f'[CMD] FAILED: {e}'); return False

# ── Frame analysis ─────────────────────────────────────────────────────────────

def mac(b): return ':'.join(f'{x:02x}' for x in b)

def analyze_frame(frame):
    """Return a compact analysis dict for a raw Ethernet frame."""
    if len(frame) < 14: return None
    dst = frame[0:6]; src = frame[6:12]
    etype = frame[12:14]
    payload = frame[14:]
    return {
        'dst_prefix': dst[:3].hex(),  # first 3 bytes of dst (frame family)
        'dst': mac(dst),
        'src': mac(src),
        'etype': etype.hex(),
        'total_len': len(frame),
        'payload_len': len(payload),
        'payload': payload,
        # sample first 64 bytes of payload for pattern matching
        'head64': payload[:64],
        # check if payload is all one value
        'all_same': len(set(payload)) <= 2 if payload else False,
        'dominant_byte': max(set(payload), key=payload.count) if payload else None,
    }

def payload_color_summary(payload, label=''):
    """
    For solid-color test modes, the payload should be repeating RGB triplets.
    Try to detect the pattern.
    """
    if not payload or len(payload) < 6:
        return
    # Try RGB triplet scan (no offset, 3-byte stride)
    for offset in range(3):
        triplets = []
        for i in range(offset, min(len(payload)-2, offset+90), 3):
            triplets.append((payload[i], payload[i+1], payload[i+2]))
        if not triplets: continue
        # Check if all triplets are the same
        unique = set(triplets)
        if len(unique) == 1:
            r,g,b = triplets[0]
            print(f'  [COLOR] {label} offset={offset}: SOLID RGB=({r},{g},{b})')
            return
        elif len(unique) <= 4:
            print(f'  [COLOR] {label} offset={offset}: {len(unique)} unique triplets: {list(unique)[:4]}')
            return
    # Fallback: byte frequency
    from collections import Counter
    freq = Counter(payload[:96])
    top3 = freq.most_common(3)
    print(f'  [COLOR] {label} top bytes: {[(hex(k),v) for k,v in top3]}')

def compare_payloads(before, after, label_b='before', label_a='after'):
    """Show which byte offsets changed between two payloads."""
    if not before or not after: return
    min_len = min(len(before), len(after))
    diffs = [i for i in range(min_len) if before[i] != after[i]]
    if not diffs:
        print(f'  [DIFF] No differences in first {min_len} bytes!')
        return
    print(f'  [DIFF] {len(diffs)} bytes changed out of {min_len}')
    print(f'  [DIFF] First 16 diff offsets: {diffs[:16]}')
    # Show before/after at first diff cluster
    start = diffs[0]
    end = min(start+48, min_len)
    print(f'  [DIFF] Before @{start}: {before[start:end].hex()}')
    print(f'  [DIFF] After  @{start}: {after[start:end].hex()}')
    # Check if diffs are evenly spaced (suggests stride)
    if len(diffs) >= 4:
        gaps = [diffs[i+1]-diffs[i] for i in range(min(len(diffs)-1,20))]
        from collections import Counter
        common_gap = Counter(gaps).most_common(1)[0]
        print(f'  [DIFF] Most common gap between diffs: {common_gap[0]} bytes (n={common_gap[1]}) — likely pixel stride')

# ── Capture phase ──────────────────────────────────────────────────────────────

def capture_phase(fd, buflen, duration, label, verbose=False):
    """Capture frames for `duration` seconds. Return list of analysis dicts."""
    print(f'\n[CAP] {label} for {duration:.1f}s...')
    results = []
    deadline = time.time() + duration
    raw_count = 0
    while time.time() < deadline:
        for frame in read_frames(fd, buflen, min(0.05, deadline-time.time())):
            raw_count += 1
            a = analyze_frame(frame)
            if a: results.append(a)
    print(f'[CAP] {raw_count} raw / {len(results)} analyzed')

    if not results:
        print('  [!] No frames — check bridge and connections')
        return results

    # Summarize frame types seen
    from collections import Counter
    by_dst = Counter(r['dst_prefix'] for r in results)
    by_len = Counter(r['total_len'] for r in results)
    print(f'  Frame families (by dst prefix):')
    for prefix, count in by_dst.most_common():
        print(f'    09:{prefix[2:4]}:{prefix[4:6]}:xx  → {count:,} frames')
    print(f'  Frame sizes: {dict(by_len.most_common(5))}')

    # Show payload color for most common frame size
    most_common_len = by_len.most_common(1)[0][0]
    samples = [r for r in results if r['total_len'] == most_common_len]
    if samples:
        payload_color_summary(samples[len(samples)//2]['payload'], label)

    if verbose and results:
        # Show first unique frame raw
        print(f'  First frame ({results[0]["total_len"]}B):')
        print(f'    DST:  {results[0]["dst"]}')
        print(f'    SRC:  {results[0]["src"]}')
        print(f'    HEAD: {results[0]["head64"].hex()}')

    return results

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', action='store_true',
        help='Auto-cycle all test modes, save reference frames to files')
    parser.add_argument('--color', metavar='MODE',
        help='Capture before/after for a single test mode (red/green/blue/white/off/grid)')
    parser.add_argument('--passive', action='store_true',
        help='Passive capture only, no commands')
    parser.add_argument('--duration', type=float, default=3.0,
        help='Capture duration per phase in seconds (default: 3)')
    parser.add_argument('--mgmt-ip', default=MGMT_IP,
        help=f'TB10 management IP (default: {MGMT_IP})')
    parser.add_argument('--iface-tb10', default=IFACE_TB10)
    parser.add_argument('--iface-tile', default=IFACE_TILE)
    args = parser.parse_args()

    print(f'\n=== Novastar Tile Protocol Decoder ===')
    print(f'TB10 output: {args.iface_tb10}  |  Tile side: {args.iface_tile}')
    print(f'Management: {args.mgmt_ip}:{MGMT_PORT}\n')

    fd_tb10, bl_tb10 = open_bpf(args.iface_tb10)

    if args.passive:
        capture_phase(fd_tb10, bl_tb10, args.duration * 2, 'PASSIVE', verbose=True)

    elif args.color:
        # Baseline (current state)
        baseline = capture_phase(fd_tb10, bl_tb10, args.duration, f'BASELINE (before {args.color})', verbose=True)

        # Fire command
        print(f'\n[CMD] Sending set_{args.color}...')
        if not send_test_mode(args.color):
            print('[!] Command failed — check management port connection')
        time.sleep(0.5)  # let TB10 settle

        # After
        after = capture_phase(fd_tb10, bl_tb10, args.duration, f'AFTER set_{args.color}', verbose=True)

        # Compare
        if baseline and after:
            print(f'\n[COMPARE] {args.color}')
            # Use median frames for comparison (avoid transient frames)
            b_sample = baseline[len(baseline)//2]
            a_sample = after[len(after)//2]

            # Check for frame structure change
            if b_sample['total_len'] != a_sample['total_len']:
                print(f'  Frame size changed: {b_sample["total_len"]} → {a_sample["total_len"]}')

            compare_payloads(b_sample['payload'], a_sample['payload'],
                           'before', f'after set_{args.color}')

            # Save reference frames
            for mode, frames, label in [('baseline', baseline, 'baseline'),
                                         (args.color, after, args.color)]:
                fname = f'ref_{label}.bin'
                mid = frames[len(frames)//2]
                with open(fname, 'wb') as f:
                    f.write(mid['payload'])
                print(f'  Saved: {fname} ({len(mid["payload"])} bytes)')

    elif args.scan:
        # Cycle all modes, save reference frame for each
        import os as _os
        _os.makedirs('ref_frames', exist_ok=True)

        modes = ['off', 'red', 'green', 'blue', 'white', 'grid']
        refs = {}

        for mode in modes:
            print(f'\n══ MODE: {mode} ══')
            send_test_mode(mode)
            time.sleep(0.5)
            frames = capture_phase(fd_tb10, bl_tb10, args.duration, mode, verbose=True)
            if frames:
                mid = frames[len(frames)//2]
                refs[mode] = mid['payload']
                fname = f'ref_frames/ref_{mode}.bin'
                with open(fname, 'wb') as f:
                    f.write(mid['payload'])
                print(f'  Saved: {fname}')

        # Compare all against 'off'
        if 'off' in refs:
            print('\n\n═══ COMPARISON vs OFF ═══')
            for mode in ['red', 'green', 'blue', 'white']:
                if mode in refs:
                    print(f'\n  ── {mode} ──')
                    compare_payloads(refs['off'], refs[mode], 'off', mode)

        # Restore off
        send_test_mode('off')

    os.close(fd_tb10)
    print('\n[DONE]')


if __name__ == '__main__':
    main()
