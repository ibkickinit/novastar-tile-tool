#!/usr/bin/env python3
"""
Novastar TB10 Plus — tile output port protocol analyzer.

Connect Mac's en9 directly to the TB10's LED tile output port.
This script captures raw Ethernet frames from the TB10's output stream,
decodes the Novastar tile protocol, and reports pixel content changes
(e.g. when test mode commands are sent via TCP 5200).

The TB10 sends ~293k frames/sec even with no tile connected.
Frame structure:
  dst MAC: 09:87:00:00:00:00   (Novastar proprietary multicast)
  src MAC: 00:00:00:00:00:00   (sending card identity)
  ethertype: ???               (to be determined)
  payload:  pixel data / control data

Usage:
  python3 tile_capture.py              # passive capture + decode
  python3 tile_capture.py --send-cmd red   # fire test command then capture
"""

import os, sys, struct, fcntl, time, binascii, select, argparse, socket, collections

IFACE = 'en9'

# ── BPF ────────────────────────────────────────────────────────────────────────

BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSHDRCMPLT = 0x80044275
BIOCPROMISC   = 0x20004269   # enable promiscuous mode

def open_bpf(iface: str) -> tuple[int, int]:
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCPROMISC, struct.pack('I', 1))
            buflen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, b'\x00'*4))[0]
            print(f'[BPF] /dev/bpf{i} on {iface}, buflen={buflen}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError('No BPF device available')


def bpf_read(fd: int, buflen: int, timeout: float = 1.0) -> list[bytes]:
    rdy, _, _ = select.select([fd], [], [], timeout)
    if not rdy:
        return []
    buf = os.read(fd, buflen)
    frames = []
    off = 0
    while off < len(buf):
        if off + 18 > len(buf):
            break
        caplen, datalen, hdrlen = struct.unpack_from('IIH', buf, off + 8)
        frame = buf[off + hdrlen: off + hdrlen + caplen]
        frames.append(frame)
        total = hdrlen + caplen
        off += (total + 3) & ~3
    return frames


# ── Novastar tile protocol decoder ─────────────────────────────────────────────

NOVA_TILE_DST = bytes.fromhex('098700000000')

def decode_frame(frame: bytes):
    """
    Decode a raw Ethernet frame from the TB10 tile port.
    Returns a dict with decoded fields, or None if not a Novastar tile frame.
    """
    if len(frame) < 14:
        return None

    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    etype   = frame[12:14]

    # Only care about Novastar tile frames
    if dst_mac != NOVA_TILE_DST:
        return None

    payload = frame[14:]
    result = {
        'dst': ':'.join(f'{b:02x}' for b in dst_mac),
        'src': ':'.join(f'{b:02x}' for b in src_mac),
        'ethertype': etype.hex(),
        'payload_len': len(payload),
        'payload_head': payload[:32].hex() if payload else '',
        'all_zero': not any(payload),
    }

    # Try to identify payload structure
    # Novastar tile frames typically carry:
    #   - A frame header with sequence/control info
    #   - Pixel data (RGB or packed format)
    if len(payload) >= 4:
        result['payload_u32_0'] = struct.unpack_from('>I', payload, 0)[0]

    # Check if payload contains recognizable pixel patterns
    if len(payload) >= 6:
        # Sample 8 evenly-spaced bytes for a quick color fingerprint
        step = max(1, len(payload) // 8)
        samples = [payload[i*step] for i in range(8)]
        result['sample_bytes'] = bytes(samples).hex()

    return result


# ── Test mode command sender ────────────────────────────────────────────────────
# (sends via TCP 5200 to 192.168.0.10 — requires management port accessible)

SENDING_CARD_IP = '192.168.0.10'
TCP_PORT = 5200

TEST_MODES = {
    'off':   0, 'normal': 0,
    'red':   2,
    'green': 3,
    'blue':  4,
    'white': 5,
    'grid':  6,
}

def nova_pkt(address: int, data: bytes, serial: int = 0) -> bytes:
    hdr = bytes([0x55, 0xAA, 0x00, serial & 0xFF, 0xFE, 0xFF, 0x01, 0xFF])
    hdr += struct.pack('<HBB', 0xFFFF, 0x01, 0x00)  # card_all, write, padding
    hdr += struct.pack('<IH', address, len(data))
    content = hdr[2:] + data
    c = (sum(content) + 0x5555) & 0xFFFF
    return hdr + data + struct.pack('<H', c)

def send_test_mode(mode_name: str) -> bool:
    mode_val = TEST_MODES.get(mode_name.lower())
    if mode_val is None:
        print(f'[CMD] Unknown mode: {mode_name}')
        return False
    pkt = nova_pkt(0x02000101, bytes([mode_val]))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((SENDING_CARD_IP, TCP_PORT))
        s.sendall(pkt)
        time.sleep(0.2)
        try:
            resp = s.recv(256)
            print(f'[CMD] set_{mode_name}={mode_val} ACK: {resp.hex()}')
        except:
            print(f'[CMD] set_{mode_name}={mode_val} sent (no response)')
        s.close()
        return True
    except Exception as e:
        print(f'[CMD] Failed to send: {e}')
        return False


# ── Analysis helpers ────────────────────────────────────────────────────────────

def summarize_frames(frames_data: list[dict]) -> dict:
    """Summarize a batch of frames: count, unique etype, payload diversity."""
    if not frames_data:
        return {}
    total = len(frames_data)
    all_zero = sum(1 for f in frames_data if f.get('all_zero'))
    etypes = collections.Counter(f['ethertype'] for f in frames_data)
    payload_lens = collections.Counter(f['payload_len'] for f in frames_data)
    # Unique first-4-byte values (frame types / control words)
    u32s = collections.Counter(f.get('payload_u32_0', 0) for f in frames_data)
    # Unique sample fingerprints
    samples = collections.Counter(f.get('sample_bytes','') for f in frames_data)

    return {
        'total': total,
        'all_zero_pct': f'{100*all_zero/total:.1f}%',
        'top_etypes': etypes.most_common(3),
        'top_payload_lens': payload_lens.most_common(3),
        'unique_u32_lead': len(u32s),
        'top_u32s': [(hex(k), v) for k,v in u32s.most_common(5)],
        'top_samples': samples.most_common(5),
    }


# ── Main ────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--send-cmd', metavar='MODE',
        help='Send test mode command before capturing (red/green/blue/white/off)')
    parser.add_argument('--capture-sec', type=float, default=5.0,
        help='Seconds to capture per phase (default: 5)')
    parser.add_argument('--iface', default=IFACE, help=f'Interface (default: {IFACE})')
    parser.add_argument('--card-ip', default=SENDING_CARD_IP,
        help=f'Sending card IP for commands (default: {SENDING_CARD_IP})')
    parser.add_argument('--cycle', action='store_true',
        help='Cycle through all test modes automatically and compare frames')
    args = parser.parse_args()

    SENDING_CARD_IP = args.card_ip
    IFACE = args.iface

    print(f'\n=== Novastar TB10 Tile Port Analyzer ===')
    print(f'Interface: {IFACE}')
    print(f'Card IP:   {SENDING_CARD_IP}:{TCP_PORT} (for commands)\n')

    fd, buflen = open_bpf(IFACE)

    def capture_phase(label: str, duration: float) -> list[dict]:
        """Capture frames for `duration` seconds, return decoded list."""
        print(f'\n[CAP] {label} — capturing {duration}s...')
        results = []
        deadline = time.time() + duration
        frame_count = 0
        while time.time() < deadline:
            frames = bpf_read(fd, buflen, timeout=min(0.5, deadline - time.time()))
            for f in frames:
                frame_count += 1
                decoded = decode_frame(f)
                if decoded:
                    results.append(decoded)
        print(f'[CAP] {frame_count} raw frames, {len(results)} Novastar tile frames')
        return results

    def print_summary(label: str, summary: dict):
        print(f'\n  ── {label} ──')
        for k, v in summary.items():
            print(f'     {k}: {v}')

    if args.cycle:
        # Capture baseline (off) → each color → back to off
        modes = ['off', 'red', 'green', 'blue', 'white', 'grid', 'off']
        snapshots = {}
        for mode in modes:
            send_test_mode(mode)
            time.sleep(0.5)  # let TB10 settle
            frames = capture_phase(f'mode={mode}', args.capture_sec)
            snapshots[mode] = summarize_frames(frames)

        print('\n\n=== COMPARISON TABLE ===')
        for mode, summary in snapshots.items():
            print_summary(mode.upper(), summary)

    else:
        # Baseline capture
        base_frames = capture_phase('BASELINE (no command)', args.capture_sec)
        base_summary = summarize_frames(base_frames)

        if args.send_cmd:
            send_test_mode(args.send_cmd)
            time.sleep(0.3)
            after_frames = capture_phase(f'AFTER set_{args.send_cmd}', args.capture_sec)
            after_summary = summarize_frames(after_frames)

            print('\n\n=== BEFORE / AFTER COMPARISON ===')
            print_summary('BASELINE', base_summary)
            print_summary(f'AFTER set_{args.send_cmd}', after_summary)

            # Highlight differences
            print('\n  ── CHANGES ──')
            for k in base_summary:
                if base_summary[k] != after_summary.get(k):
                    print(f'     {k}: {base_summary[k]} → {after_summary.get(k)}')

        else:
            print('\n=== BASELINE SUMMARY ===')
            print_summary('BASELINE', base_summary)

            # Print first 5 unique frames raw
            seen = set()
            print('\n  First unique Novastar frames:')
            for f in base_frames:
                key = f['ethertype'] + f['payload_head']
                if key not in seen:
                    seen.add(key)
                    print(f'    etype={f["ethertype"]} len={f["payload_len"]}  '
                          f'head={f["payload_head"]}')
                if len(seen) >= 8:
                    break

    os.close(fd)
    print('\n[DONE]')


if __name__ == '__main__':
    main()
