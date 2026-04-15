#!/usr/bin/env python3
"""
brightness_hunt.py — find the brightness command in Novastar captures.

Two modes:

1. DIFF MODE (default): Compare a "transition" capture against a "static"
   baseline. Reports any frame content that appears during transitions but
   not in the baseline — the brightness command should show up here.

   python3 brightness_hunt.py diff static_0pct.pcapng bounce_0_1.pcapng
   python3 brightness_hunt.py diff static_0pct.pcapng bounce_99_100.pcapng

2. LIVE MODE: Single-interface BPF capture. Logs every unique frame type
   and flags any that appear fewer than --rare-threshold times (one-shot
   commands). Use this on bridge0 during a brightness change.

   sudo python3 brightness_hunt.py live --iface bridge0 --out ~/Desktop/bridge0.pcapng

3. SWEEP MODE: Read a pcapng and produce a timeline of ALL unique frame
   types per time bucket, so you can see what changes during a sweep.

   python3 brightness_hunt.py sweep brightness_sweep.pcapng --bucket 0.5
"""

import os, sys, struct, fcntl, select, time, argparse, collections
from typing import Optional

# ── pcapng reader (shared with decode_control.py) ─────────────────────────────

PCAPNG_SHB  = 0x0A0D0D0A
PCAPNG_IDB  = 0x00000001
PCAPNG_EPB  = 0x00000006
PCAPNG_SPB  = 0x00000003

def read_block(f):
    hdr = f.read(8)
    if len(hdr) < 8:
        return None, None, None
    btype, blen = struct.unpack('<II', hdr)
    body = f.read(blen - 12)
    f.read(4)
    return btype, blen, body

def iter_pcapng(path):
    """Yield (timestamp_us, frame_bytes) for every frame."""
    with open(path, 'rb') as f:
        btype, blen, body = read_block(f)
        if btype != PCAPNG_SHB:
            raise ValueError(f'Not a pcapng file: {path}')
        iface_ts_resolutions = []
        while True:
            btype, blen, body = read_block(f)
            if btype is None:
                break
            if btype == PCAPNG_IDB:
                opts_off = 4
                tsresol = 6
                while opts_off + 4 <= len(body):
                    code, olen = struct.unpack_from('<HH', body, opts_off)
                    opts_off += 4
                    val = body[opts_off:opts_off + olen]
                    opts_off += (olen + 3) & ~3
                    if code == 0:
                        break
                    if code == 9:
                        tsresol = val[0]
                if tsresol & 0x80:
                    res = 2 ** (tsresol & 0x7F)
                else:
                    res = 10 ** tsresol
                iface_ts_resolutions.append(res)
            elif btype in (PCAPNG_EPB, PCAPNG_SPB):
                if btype == PCAPNG_EPB:
                    iface_id = struct.unpack_from('<I', body, 0)[0]
                    ts_hi, ts_lo = struct.unpack_from('<II', body, 4)
                    cap_len = struct.unpack_from('<I', body, 12)[0]
                    frame = body[20:20 + cap_len]
                    res = iface_ts_resolutions[iface_id] if iface_id < len(iface_ts_resolutions) else 1_000_000
                    ts_us = ((ts_hi << 32) | ts_lo) * 1_000_000 // res
                else:
                    cap_len = struct.unpack_from('<I', body, 0)[0]
                    frame = body[4:4 + cap_len]
                    ts_us = 0
                yield ts_us, frame

def frame_type_key(frame: bytes) -> tuple:
    """Return a (dst_prefix_2, etype, frame_len) key for frame type classification."""
    if len(frame) < 14:
        return (frame[:2].hex(), '', len(frame))
    return (frame[0:2].hex(), frame[12:14].hex(), len(frame))

def hexdump(data, indent='    ', width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{indent}{i:04x}  {hex_part:<{width*3}}  {asc_part}')
    return '\n'.join(lines)

# ── BPF ───────────────────────────────────────────────────────────────────────

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
            print(f'[BPF] /dev/bpf{i} → {iface}  buflen={buflen}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError(f'No BPF device for {iface}')

def read_bpf_frames(fd, buflen, timeout=0.05):
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

# ── pcapng writer (minimal) ───────────────────────────────────────────────────

def _pad4(n): return (n + 3) & ~3

def pcapng_shb():
    body  = struct.pack('<IHH', 0x1A2B3C4D, 1, 0)
    body += struct.pack('<q', -1)
    total = 12 + len(body)
    return struct.pack('<II', 0x0A0D0D0A, total) + body + struct.pack('<I', total)

def pcapng_idb(name='', snaplen=65535):
    body = struct.pack('<HHI', 1, 0, snaplen)
    if name:
        nb = name.encode()
        opt = struct.pack('<HH', 2, len(nb)) + nb + b'\x00'*(_pad4(len(nb))-len(nb))
        opt += struct.pack('<HH', 0, 0)
        body += opt
    total = 12 + len(body)
    return struct.pack('<II', 2, total) + body + struct.pack('<I', total)

def pcapng_epb(ts_us, frame):
    caplen = len(frame)
    padded = _pad4(caplen)
    body  = struct.pack('<I', 0)
    body += struct.pack('<II', (ts_us >> 32) & 0xFFFFFFFF, ts_us & 0xFFFFFFFF)
    body += struct.pack('<II', caplen, caplen)
    body += frame + b'\x00'*(padded - caplen)
    total = 12 + len(body)
    return struct.pack('<II', 6, total) + body + struct.pack('<I', total)

# ── DIFF MODE ─────────────────────────────────────────────────────────────────

def cmd_diff(args):
    """
    Load baseline pcapng(s), then compare transition pcapng against them.
    Look for any frame payload (first 64 bytes) that appears during the
    transition but NOT in any baseline capture.
    """
    # Load baseline — can be multiple files
    print(f'Loading baseline(s): {args.baselines}')
    baseline_payloads = set()    # set of bytes (first 64 bytes of each frame payload)
    baseline_type_counts = collections.Counter()

    for path in args.baselines:
        count = 0
        for _, frame in iter_pcapng(path):
            if len(frame) < 14:
                continue
            # Classify by dst[0:2] prefix
            key = frame[0:2].hex()
            baseline_type_counts[key] += 1
            payload_sample = bytes(frame[14:14+args.sample])
            baseline_payloads.add(payload_sample)
            count += 1
        print(f'  {path}: {count:,} frames')

    print(f'\nBaseline: {sum(baseline_type_counts.values()):,} total frames')
    print(f'  Frame type counts (dst[0:2]):')
    for prefix, cnt in sorted(baseline_type_counts.items(), key=lambda x: -x[1]):
        print(f'    {prefix}: {cnt:,}')
    print(f'  Unique {args.sample}-byte payload samples: {len(baseline_payloads):,}\n')

    # Load transition capture
    print(f'Loading transition: {args.transition}')
    novel_frames = []   # frames not seen in any baseline
    transition_type_counts = collections.Counter()
    total_trans = 0

    for ts_us, frame in iter_pcapng(args.transition):
        if len(frame) < 14:
            continue
        key = frame[0:2].hex()
        transition_type_counts[key] += 1
        total_trans += 1
        payload_sample = bytes(frame[14:14+args.sample])
        if payload_sample not in baseline_payloads:
            novel_frames.append((ts_us, frame))

    print(f'  {total_trans:,} total frames')
    print(f'  Frame type counts (dst[0:2]):')
    for prefix, cnt in sorted(transition_type_counts.items(), key=lambda x: -x[1]):
        print(f'    {prefix}: {cnt:,}')
    print(f'\n  NOVEL frames (not in baseline): {len(novel_frames):,}')

    if not novel_frames:
        print('\n  No novel frame payloads found.')
        print('  The brightness command is either:')
        print('    a) Encoded within a frame type whose payload matches baseline exactly')
        print('    b) Hidden in a field we are not sampling (header fields, length, timing)')
        print('    c) Not yet captured (missed by BPF during transition window)')
        _deep_analysis(args, baseline_type_counts, transition_type_counts)
        return

    print(f'\n--- NOVEL FRAMES ---')
    # Group by frame prefix
    by_prefix = collections.defaultdict(list)
    for ts_us, frame in novel_frames:
        prefix = frame[0:2].hex()
        by_prefix[prefix].append((ts_us, frame))

    for prefix, frames in sorted(by_prefix.items(), key=lambda x: -len(x[1])):
        dst_s = ':'.join(frames[0][1][i:i+1].hex() for i in range(6)) if len(frames[0][1]) >= 6 else prefix
        print(f'\n  Prefix {prefix}: {len(frames):,} novel frames')
        # Show first and last few
        show = frames[:3] + (frames[-2:] if len(frames) > 5 else [])
        for ts_us, frame in show:
            ts_s = ts_us / 1_000_000
            dst_s = ':'.join(f'{b:02x}' for b in frame[0:6])
            etype = frame[12:14].hex()
            payload = frame[14:]
            print(f'    [{ts_s:8.3f}s]  dst={dst_s}  etype=0x{etype}  len={len(frame)}')
            print(hexdump(payload[:args.sample], indent='      '))


def _deep_analysis(args, baseline_counts, transition_counts):
    """When no novel payload bytes found, look for structural differences."""
    print('\n--- DEEP ANALYSIS (no novel payloads) ---')

    # Check if any new PREFIX appeared in transition
    new_prefixes = set(transition_counts.keys()) - set(baseline_counts.keys())
    if new_prefixes:
        print(f'\n  NEW dst prefixes in transition (not in baseline): {new_prefixes}')
    else:
        print(f'\n  No new dst prefixes in transition capture.')

    # Check for rate changes in any prefix type
    print('\n  Rate comparison (baseline vs transition):')
    all_prefixes = set(baseline_counts) | set(transition_counts)
    for prefix in sorted(all_prefixes):
        bc = baseline_counts.get(prefix, 0)
        tc = transition_counts.get(prefix, 0)
        ratio = tc / bc if bc > 0 else float('inf')
        note = '  *** CHANGED' if abs(ratio - 1.0) > 0.1 and bc > 10 else ''
        print(f'    {prefix}: baseline={bc:,}  transition={tc:,}  ratio={ratio:.2f}{note}')

    # Check the 09:2d frames specifically — look at first 2 bytes of payload
    # to find any new "opcode" we haven't seen before
    print('\n  Checking 09:2d payload byte-0 values in transition vs baseline...')
    _check_payload_byte0(args.baselines, args.transition, prefix_filter=b'\x09\x2d')

    # Also check 09:3c
    print('\n  Checking 09:3c payload byte-0 values in transition vs baseline...')
    _check_payload_byte0(args.baselines, args.transition, prefix_filter=b'\x09\x3c')

    # Check pixel frame (09:1e) payload — do pixel VALUES change during transition?
    print('\n  Checking 09:1e pixel values in transition vs baseline...')
    _check_pixel_values(args.baselines, args.transition)


def _check_payload_byte0(baselines, transition, prefix_filter):
    base_b0 = collections.Counter()
    for path in baselines:
        for _, frame in iter_pcapng(path):
            if len(frame) >= 15 and frame[0:2] == prefix_filter:
                base_b0[frame[14]] += 1
    trans_b0 = collections.Counter()
    for _, frame in iter_pcapng(transition):
        if len(frame) >= 15 and frame[0:2] == prefix_filter:
            trans_b0[frame[14]] += 1
    if not base_b0 and not trans_b0:
        print(f'    No frames with prefix {prefix_filter.hex()} found.')
        return
    all_b0 = set(base_b0) | set(trans_b0)
    new_b0 = set(trans_b0) - set(base_b0)
    if new_b0:
        print(f'    NEW byte-0 values in transition: {[hex(v) for v in sorted(new_b0)]}')
    else:
        print(f'    No new byte-0 values.  Seen: {sorted(hex(k) for k in all_b0)}')


def _check_pixel_values(baselines, transition):
    """Check if any pixel frame carries non-standard values during transition."""
    base_vals = set()
    for path in baselines:
        for _, frame in iter_pcapng(path):
            if len(frame) >= 15 and frame[0:2] == b'\x09\x1e' and frame[2] != 0:
                for b in frame[14:14+48]:
                    base_vals.add(b)
    trans_vals = set()
    for _, frame in iter_pcapng(transition):
        if len(frame) >= 15 and frame[0:2] == b'\x09\x1e' and frame[2] != 0:
            for b in frame[14:14+48]:
                trans_vals.add(b)
    new_vals = trans_vals - base_vals
    if new_vals:
        print(f'  NEW pixel values in transition frames: {sorted(new_vals)} ({[hex(v) for v in sorted(new_vals)]})')
        print(f'  *** THIS IS THE BRIGHTNESS SIGNAL — pixel values change with brightness!')
    else:
        print(f'  Pixel values same in both.  Values seen: {sorted(trans_vals)} ({[hex(v) for v in sorted(trans_vals)]})')
        if trans_vals == {0xBF}:
            print(f'  Confirmed: only 0xBF seen — brightness does NOT change pixel values.')

# ── SWEEP MODE ────────────────────────────────────────────────────────────────

def cmd_sweep(args):
    """Timeline of ALL unique frame types per time bucket."""
    bucket_us = int(args.bucket * 1_000_000)
    # key = bucket_index, value = Counter of (dst[0:2], etype)
    buckets = collections.defaultdict(lambda: collections.defaultdict(int))
    frame_examples = {}   # (dst[0:2], etype) -> first frame seen

    print(f'Reading {args.pcapng}  (bucket={args.bucket}s)')
    total = 0
    for ts_us, frame in iter_pcapng(args.pcapng):
        if len(frame) < 14:
            continue
        bk = ts_us // bucket_us if bucket_us > 0 else ts_us
        prefix = frame[0:2].hex()
        etype  = frame[12:14].hex()
        key = (prefix, etype)
        buckets[bk][key] += 1
        if key not in frame_examples:
            frame_examples[key] = frame
        total += 1

    print(f'{total:,} frames in {len(buckets)} buckets\n')

    # Find all unique keys across all buckets
    all_keys = set()
    for bk_data in buckets.values():
        all_keys.update(bk_data.keys())

    # Sort keys by total count descending
    key_totals = collections.Counter()
    for bk_data in buckets.values():
        for k, c in bk_data.items():
            key_totals[k] += c
    sorted_keys = [k for k, _ in key_totals.most_common()]

    # Print header
    col_w = 14
    header = f'  {"Time":>7}s'
    for prefix, etype in sorted_keys:
        label = f'{prefix}/{etype}'
        header += f'  {label:>{col_w}}'
    print(header)
    print('  ' + '-' * (8 + len(sorted_keys) * (col_w + 2)))

    for bk in sorted(buckets.keys()):
        ts_s = bk * args.bucket
        row = f'  {ts_s:8.1f}s'
        bk_data = buckets[bk]
        bk_total = sum(bk_data.values())
        for key in sorted_keys:
            cnt = bk_data.get(key, 0)
            pct = cnt / bk_total * 100 if bk_total else 0
            if cnt == 0:
                row += f'  {"":>{col_w}}'
            else:
                cell = f'{cnt}({pct:.0f}%)'
                row += f'  {cell:>{col_w}}'
        print(row)

    # Summary: show payload of each type
    print('\n--- Frame type payloads (first example) ---')
    for key in sorted_keys:
        prefix, etype = key
        frame = frame_examples[key]
        dst_s = ':'.join(f'{b:02x}' for b in frame[0:6])
        total_cnt = key_totals[key]
        print(f'\n  dst={dst_s}  etype=0x{etype}  total={total_cnt:,}  len={len(frame)}')
        print(hexdump(frame[14:14+32], indent='    '))

# ── LIVE MODE ─────────────────────────────────────────────────────────────────

def cmd_live(args):
    """Live BPF capture on a single interface. Logs rare frames in real time."""
    fd, buflen = open_bpf(args.iface)
    out_file = open(args.out, 'wb') if args.out else None
    if out_file:
        out_file.write(pcapng_shb())
        out_file.write(pcapng_idb(args.iface))
        print(f'[PCAP] Writing to {args.out}')

    print(f'Capturing on {args.iface}  (rare_threshold={args.rare_threshold})')
    print(f'Ctrl+C to stop. Will highlight any frame type seen < {args.rare_threshold} times.\n')
    print(f'  {"Time":<10} {"Type":<25} {"Count":>7}  {"Note"}')
    print(f'  {"─"*10} {"─"*25} {"─"*7}  {"─"*30}')

    # key = (dst[0:2], etype), value = count
    type_counts = collections.Counter()
    rare_seen   = {}   # type_key -> first example frame

    # Live display: print a summary line every interval
    next_print = time.time() + args.interval
    frame_total = 0

    try:
        while True:
            now_ts = time.time()
            for frame in read_bpf_frames(fd, buflen, timeout=0.02):
                frame_total += 1
                ts_us = int(now_ts * 1_000_000)
                if out_file:
                    out_file.write(pcapng_epb(ts_us, frame))
                if len(frame) < 14:
                    continue
                prefix = frame[0:2].hex()
                etype  = frame[12:14].hex()
                key = (prefix, etype)
                type_counts[key] += 1
                cnt = type_counts[key]
                # Flag when a type is first seen, or when count is still rare
                if cnt <= args.rare_threshold:
                    t = time.strftime('%H:%M:%S')
                    dst_s = ':'.join(f'{b:02x}' for b in frame[0:6])
                    note = ''
                    if cnt == 1:
                        note = '*** FIRST SEEN ***'
                        rare_seen[key] = frame
                    elif cnt == args.rare_threshold:
                        note = f'(now at threshold {args.rare_threshold})'
                    if note:
                        print(f'  {t:<10} {dst_s:<25} {cnt:>7}  {note}')
                        if len(frame) >= 14:
                            print(hexdump(frame[14:14+args.sample], indent='             '))

            now = time.time()
            if now >= next_print:
                next_print = now + args.interval
                t = time.strftime('%H:%M:%S')
                print(f'  {t}  total={frame_total:,}  types={len(type_counts)}  '
                      f'rare(<={args.rare_threshold}): {sum(1 for c in type_counts.values() if c <= args.rare_threshold)}')
    except KeyboardInterrupt:
        print(f'\n[DONE]  {frame_total:,} frames captured  {len(type_counts)} unique types')
        if rare_seen:
            print(f'\nRare frame types (seen < {args.rare_threshold} times):')
            for key, frame in rare_seen.items():
                prefix, etype = key
                dst_s = ':'.join(f'{b:02x}' for b in frame[0:6])
                cnt = type_counts[key]
                print(f'  dst={dst_s}  etype=0x{etype}  count={cnt}  len={len(frame)}')
                print(hexdump(frame[14:], indent='    '))
    finally:
        os.close(fd)
        if out_file:
            out_file.flush()
            out_file.close()
            print(f'[PCAP] Saved → {args.out}')

# ── main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Novastar brightness command finder')
    sub = parser.add_subparsers(dest='cmd', required=True)

    # diff
    p = sub.add_parser('diff', help='Compare transition capture vs static baseline')
    p.add_argument('baselines', nargs='+', help='One or more baseline pcapng files')
    p.add_argument('transition', help='Transition (brightness change) pcapng')
    p.add_argument('--sample', type=int, default=64,
                   help='Bytes of payload to fingerprint (default: 64)')

    # sweep
    p = sub.add_parser('sweep', help='Timeline of all frame types per time bucket')
    p.add_argument('pcapng', help='pcapng file')
    p.add_argument('--bucket', type=float, default=1.0,
                   help='Time bucket in seconds (default: 1.0)')

    # live
    p = sub.add_parser('live', help='Live BPF capture, flag one-shot frames')
    p.add_argument('--iface', default='bridge0', help='Interface to capture on (default: bridge0)')
    p.add_argument('--out', default=None, help='Write pcapng to this file')
    p.add_argument('--interval', type=float, default=5.0,
                   help='Status print interval in seconds (default: 5)')
    p.add_argument('--rare-threshold', type=int, default=5,
                   help='Flag frame types seen this many times or fewer (default: 5)')
    p.add_argument('--sample', type=int, default=48,
                   help='Bytes of payload to show for rare frames (default: 48)')

    args = parser.parse_args()

    if args.cmd == 'diff':
        cmd_diff(args)
    elif args.cmd == 'sweep':
        cmd_sweep(args)
    elif args.cmd == 'live':
        cmd_live(args)

if __name__ == '__main__':
    main()
