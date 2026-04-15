#!/usr/bin/env python3
"""
VX1000 control frame decoder.

Reads a pcapng and extracts all 09:2d (and 09:3c) control frames,
dumping raw payload hex at regular intervals so you can compare
what changes during a brightness sweep.

Usage:
    python3 decode_control.py vx1000_session.pcapng
    python3 decode_control.py vx1000_session.pcapng --bucket 1.0   # 1-second buckets
    python3 decode_control.py vx1000_session.pcapng --unique        # deduplicate identical payloads

The goal: find which payload bytes change when brightness changes.
"""

import sys, struct, argparse, collections

# ── pcapng reader ──────────────────────────────────────────────────────────────

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
    f.read(4)  # trailing length
    return btype, blen, body

def iter_pcapng(path):
    """Yield (timestamp_us, frame_bytes) for every captured frame."""
    with open(path, 'rb') as f:
        btype, blen, body = read_block(f)
        if btype != PCAPNG_SHB:
            raise ValueError('Not a pcapng file')

        ts_resolution = 1_000_000  # default microseconds
        iface_ts_resolutions = []

        while True:
            btype, blen, body = read_block(f)
            if btype is None:
                break

            if btype == PCAPNG_IDB:
                # Interface Description Block — parse tsresol option if present
                snap = struct.unpack_from('<HH', body, 0)
                opts_off = 4
                tsresol = 6  # default: 10^-6 = microseconds
                while opts_off + 4 <= len(body):
                    code, olen = struct.unpack_from('<HH', body, opts_off)
                    opts_off += 4
                    val = body[opts_off:opts_off + olen]
                    opts_off += (olen + 3) & ~3
                    if code == 0:  # opt_endofopt
                        break
                    if code == 9:  # if_tsresol
                        tsresol = val[0]
                if tsresol & 0x80:
                    ts_resolution = 2 ** (tsresol & 0x7F)
                else:
                    ts_resolution = 10 ** tsresol
                iface_ts_resolutions.append(ts_resolution)

            elif btype in (PCAPNG_EPB, PCAPNG_SPB):
                if btype == PCAPNG_EPB:
                    iface_id = struct.unpack_from('<I', body, 0)[0]
                    ts_hi, ts_lo = struct.unpack_from('<II', body, 4)
                    cap_len = struct.unpack_from('<I', body, 12)[0]
                    frame = body[20:20 + cap_len]
                    res = iface_ts_resolutions[iface_id] if iface_id < len(iface_ts_resolutions) else 1_000_000
                    ts_us = ((ts_hi << 32) | ts_lo) * 1_000_000 // res
                else:  # SPB
                    iface_id = 0
                    cap_len = struct.unpack_from('<I', body, 0)[0]
                    frame = body[4:4 + cap_len]
                    ts_us = 0
                yield ts_us, iface_id, frame

# ── main ───────────────────────────────────────────────────────────────────────

def hexdump(data, indent='    ', width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{indent}{i:04x}  {hex_part:<{width*3}}  {asc_part}')
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='VX1000 control frame decoder')
    parser.add_argument('pcapng', help='pcapng capture file')
    parser.add_argument('--bucket', type=float, default=0.5,
                        help='Time bucket size in seconds (default: 0.5)')
    parser.add_argument('--unique', action='store_true',
                        help='Only print a payload when it differs from previous')
    parser.add_argument('--prefix', default='092d',
                        help='Frame dst-mac prefix to filter (hex, default: 092d). '
                             'Use 09 for all Novastar control types.')
    parser.add_argument('--max-payload', type=int, default=64,
                        help='Bytes of payload to print (default: 64)')
    parser.add_argument('--out', default=None,
                        help='Write output to this file in addition to stdout')
    parser.add_argument('--iface', type=int, default=None, metavar='IDX',
                        help='Filter by interface index (0=en11/VX1000 side, 1=en9/tile side). '
                             'Omit to show all interfaces.')
    args = parser.parse_args()

    prefix = bytes.fromhex(args.prefix)
    bucket_us = int(args.bucket * 1_000_000)

    out_file = open(args.out, 'w') if args.out else None

    def emit(*a, **kw):
        print(*a, **kw)
        if out_file:
            print(*a, **kw, file=out_file)

    emit(f'Reading {args.pcapng}')
    emit(f'Filtering: dst MAC prefix = {args.prefix}')
    if args.iface is not None:
        emit(f'Interface filter: iface_id={args.iface}')
    emit(f'Bucket size: {args.bucket}s | Unique-only: {args.unique}')
    emit()

    # Collect frames per bucket
    # bucket_key = ts_us // bucket_us
    # value = list of (ts_us, dst_mac, etype, payload)
    buckets = collections.defaultdict(list)
    total = 0

    for ts_us, iface_id, frame in iter_pcapng(args.pcapng):
        if args.iface is not None and iface_id != args.iface:
            continue
        if len(frame) < 14:
            continue
        dst = frame[0:6]
        if not dst[:len(prefix)] == prefix:
            continue
        etype = frame[12:14]
        payload = frame[14:]
        bk = ts_us // bucket_us if bucket_us > 0 else ts_us
        buckets[bk].append((ts_us, dst, etype, payload))
        total += 1

    emit(f'Found {total} matching frames in {len(buckets)} buckets\n')
    if total == 0:
        emit('No matching frames. Check --prefix or try: --prefix 09')
        if out_file:
            out_file.close()
        return

    prev_payload = None
    for bk in sorted(buckets.keys()):
        frames = buckets[bk]
        ts_s = frames[0][0] / 1_000_000
        # Pick one representative frame from this bucket — last one seen
        _, dst, etype, payload = frames[-1]
        dst_s = ':'.join(f'{b:02x}' for b in dst)
        etype_s = f'0x{etype.hex()}'

        trunc = payload[:args.max_payload]
        same = (trunc == (prev_payload[:args.max_payload] if prev_payload is not None else None))

        if args.unique and same:
            continue

        emit(f'[{ts_s:9.3f}s] {dst_s}  etype={etype_s}  frames_in_bucket={len(frames)}')
        emit(f'  payload ({len(payload)} bytes, showing {len(trunc)}):')
        emit(hexdump(trunc))

        # Highlight differences from previous
        if prev_payload is not None and not same:
            diff_bytes = [i for i in range(min(len(trunc), len(prev_payload[:args.max_payload])))
                          if trunc[i] != prev_payload[i]]
            if diff_bytes:
                emit(f'  CHANGED at byte offsets: {diff_bytes}')
                emit(f'  prev: {" ".join(f"{prev_payload[i]:02x}" for i in diff_bytes)}')
                emit(f'  now:  {" ".join(f"{trunc[i]:02x}" for i in diff_bytes)}')
        emit()

        prev_payload = payload

    if out_file:
        out_file.close()
        print(f'\n[saved to {args.out}]')

if __name__ == '__main__':
    main()
