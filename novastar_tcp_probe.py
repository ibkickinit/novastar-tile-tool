#!/usr/bin/env python3
"""
Novastar TB10 Plus TCP probe via raw BPF.
Implements a minimal TCP state machine over raw Ethernet frames,
bypassing macOS routing entirely.

TB10 Plus:  192.168.0.10  MAC: 54:b5:6c:26:37:9f
Mac (en9):  192.168.0.100 MAC: 4c:ea:41:64:67:d8
Port:       TCP 5200
"""

import os, sys, struct, fcntl, socket, time, binascii, select

IFACE   = 'en9'
SRC_MAC = bytes.fromhex('4cea416467d8')
DST_MAC = bytes.fromhex('54b56c26379f')
SRC_IP  = '192.168.0.100'
DST_IP  = '192.168.0.10'
PORT    = 5200
SRC_PORT = 54321

# macOS BPF ioctls
BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSHDRCMPLT = 0x80044275


# ── BPF ────────────────────────────────────────────────────────────────────────

def open_bpf(iface: str) -> tuple[int, int]:
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            fcntl.ioctl(fd, BIOCSETIF, struct.pack('16s', iface.encode()))
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))
            buflen = struct.unpack('I', fcntl.ioctl(fd, BIOCGBLEN, b'\x00'*4))[0]
            print(f'[BPF] /dev/bpf{i} on {iface}, buflen={buflen}')
            return fd, buflen
        except OSError:
            continue
    raise RuntimeError('No BPF device available')


def bpf_read(fd: int, buflen: int, timeout: float = 2.0) -> list[bytes]:
    """Read one BPF buffer, return list of raw Ethernet frames."""
    rdy, _, _ = select.select([fd], [], [], timeout)
    if not rdy:
        return []
    buf = os.read(fd, buflen)
    frames = []
    off = 0
    while off < len(buf):
        # BPF header: timeval (8 or 16 bytes) + caplen(4) + datalen(4) + hdrlen(2)
        if off + 18 > len(buf):
            break
        # macOS BPF header is bpf_hdr: struct timeval (8 bytes) + caplen + datalen + hdrlen
        caplen, datalen, hdrlen = struct.unpack_from('IIH', buf, off + 8)
        frame = buf[off + hdrlen: off + hdrlen + caplen]
        frames.append(frame)
        # Align to next BPF_WORDALIGN (4 bytes)
        total = hdrlen + caplen
        off += (total + 3) & ~3
    return frames


# ── Packet building ─────────────────────────────────────────────────────────────

def cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def make_ip(proto: int, payload: bytes) -> bytes:
    src = socket.inet_aton(SRC_IP)
    dst = socket.inet_aton(DST_IP)
    hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0, src, dst)
    return hdr[:10] + struct.pack('!H', cksum(hdr)) + hdr[12:] + payload


def make_tcp(sport: int, dport: int, seq: int, ack: int,
             flags: int, payload: bytes = b'') -> bytes:
    src = socket.inet_aton(SRC_IP)
    dst = socket.inet_aton(DST_IP)
    hdr = struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack,
        0x50, flags, 65535, 0, 0)
    pseudo = src + dst + b'\x00\x06' + struct.pack('!H', len(hdr) + len(payload))
    c = cksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('!H', c) + hdr[18:]
    return hdr + payload


def eth(payload: bytes) -> bytes:
    return DST_MAC + SRC_MAC + b'\x08\x00' + payload


def arp_reply_for_gateway() -> bytes:
    """Reply to TB10's ARP for 192.168.0.1 - pretend we are the gateway."""
    ARP_ET = b'\x08\x06'
    pkt = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
    pkt += SRC_MAC + socket.inet_aton('192.168.0.1')
    pkt += DST_MAC + socket.inet_aton('192.168.0.10')
    pkt += b'\x00' * 18
    return DST_MAC + SRC_MAC + ARP_ET + pkt


# ── Novastar protocol ──────────────────────────────────────────────────────────

def nova_pkt(address: int, data: bytes, io_dir: int = 0x01, serial: int = 0) -> bytes:
    hdr = bytes([0x55, 0xAA, 0x00, serial & 0xFF, 0xFE, 0xFF, 0x01, 0xFF])
    hdr += struct.pack('<HBB', 0xFFFF, io_dir, 0x00)
    hdr += struct.pack('<IH', address, len(data))
    content = hdr[2:] + data
    c = (sum(content) + 0x5555) & 0xFFFF
    return hdr + data + struct.pack('<H', c)


CMDS = [
    ('read_brightness', 0x02000001, b'\x00', 0x00),
    ('read_test_mode',  0x02000101, b'\x00', 0x00),
    ('set_red',         0x02000101, bytes([0x02]), 0x01),
    ('set_green',       0x02000101, bytes([0x03]), 0x01),
    ('set_blue',        0x02000101, bytes([0x04]), 0x01),
    ('set_white',       0x02000101, bytes([0x05]), 0x01),
    ('set_normal',      0x02000101, bytes([0x00]), 0x01),
]


# ── TCP mini state machine ─────────────────────────────────────────────────────

def wait_for(fd, buflen, src_ip, dport,
             flags_mask, flags_val, timeout=3.0):
    """Wait for a TCP frame matching given flags from src_ip."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        frames = bpf_read(fd, buflen, timeout=min(remaining, 0.5))
        for frame in frames:
            if len(frame) < 54:
                continue
            # Check ethertype IPv4
            if frame[12:14] != b'\x08\x00':
                continue
            # Check IP proto TCP (6)
            if frame[23] != 6:
                continue
            # Check source IP
            if socket.inet_ntoa(frame[26:30]) != src_ip:
                continue
            # Check dest port matches our src port
            tcp_off = 14 + 20
            if struct.unpack('!H', frame[tcp_off+2:tcp_off+4])[0] != dport:
                continue
            tcp_flags = frame[tcp_off + 13]
            if (tcp_flags & flags_mask) == flags_val:
                return frame
    return None


def run():
    fd, buflen = open_bpf(IFACE)

    # Send ARP reply so TB10 stops hunting for gateway
    os.write(fd, arp_reply_for_gateway())
    print('[ARP] Sent gateway spoof to TB10 Plus')
    time.sleep(0.2)

    seq = 0x12345678
    sport = SRC_PORT

    # ── SYN ──────────────────────────────────────────────────────────────────
    syn = eth(make_ip(6, make_tcp(sport, PORT, seq, 0, 0x02)))
    os.write(fd, syn)
    print(f'[TCP] SYN sent (seq={seq})')

    # ── Wait for SYN-ACK ─────────────────────────────────────────────────────
    frame = wait_for(fd, buflen, DST_IP, sport, 0x12, 0x12, timeout=4)
    if frame is None:
        print('[TCP] No SYN-ACK received — TB10 may not accept TCP on port 5200')
        os.close(fd)
        return

    tcp_off = 14 + 20
    srv_seq = struct.unpack('!I', frame[tcp_off+4:tcp_off+8])[0]
    srv_ack = struct.unpack('!I', frame[tcp_off+8:tcp_off+12])[0]
    print(f'[TCP] SYN-ACK received (srv_seq={srv_seq}, ack={srv_ack})')
    seq += 1  # SYN consumes 1 seq

    # ── ACK ──────────────────────────────────────────────────────────────────
    ack_pkt = eth(make_ip(6, make_tcp(sport, PORT, seq, srv_seq + 1, 0x10)))
    os.write(fd, ack_pkt)
    print('[TCP] ACK sent — connection established')
    time.sleep(0.1)

    # ── Send Novastar commands ────────────────────────────────────────────────
    ack_num = srv_seq + 1
    for i, (name, addr, data, io_dir) in enumerate(CMDS):
        payload = nova_pkt(addr, data, io_dir, i)
        psh = eth(make_ip(6, make_tcp(sport, PORT, seq, ack_num, 0x18, payload)))
        os.write(fd, psh)
        print(f'[TX]  {name}: {binascii.hexlify(payload).decode()}')

        # Wait for ACK or data response
        resp = wait_for(fd, buflen, DST_IP, sport, 0x10, 0x10, timeout=2)
        if resp:
            tcp_data_off = tcp_off + ((resp[tcp_off + 12] >> 4) * 4)
            data_payload = resp[tcp_data_off:]
            if data_payload:
                print(f'[RX]  {name}: {binascii.hexlify(data_payload).decode()}')
                seq += len(payload)
                ack_num = struct.unpack('!I', resp[tcp_off+4:tcp_off+8])[0] + len(data_payload)
                # Send ACK for data
                ack2 = eth(make_ip(6, make_tcp(sport, PORT, seq + len(payload), ack_num, 0x10)))
                os.write(fd, ack2)
            else:
                print(f'[RX]  {name}: ACK (no data yet)')
                seq += len(payload)
        else:
            print(f'[RX]  {name}: no response')
            seq += len(payload)

        time.sleep(1.5)

    # ── FIN ──────────────────────────────────────────────────────────────────
    fin = eth(make_ip(6, make_tcp(sport, PORT, seq, ack_num, 0x11)))
    os.write(fd, fin)
    print('[TCP] FIN sent')

    os.close(fd)
    print('[DONE]')


if __name__ == '__main__':
    # Also start tcpdump capture
    import subprocess, threading

    out = os.path.expanduser('~/Desktop/novastar_tcp.pcap')
    proc = subprocess.Popen(
        ['tcpdump', '-i', IFACE, '-s', '0', '-w', out, '--immediate-mode'],
        stderr=subprocess.DEVNULL)

    time.sleep(0.3)
    try:
        run()
    finally:
        time.sleep(1)
        proc.terminate()
        print(f'[CAP] Saved to {out}')
