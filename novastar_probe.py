#!/usr/bin/env python3
"""
Novastar TB10 Plus management port probe.
Sends protocol commands via raw BPF Ethernet frames on macOS,
bypassing IP routing. Captures responses via tcpdump.

TB10 Plus:  192.168.0.10  MAC: 54:b5:6c:26:37:9f
Mac (en9):  192.168.0.100 MAC: 4c:ea:41:64:67:d8
"""

import os, sys, struct, fcntl, socket, time, threading, subprocess, binascii

# --- Network config ---
IFACE       = 'en9'
SRC_MAC     = bytes.fromhex('4cea416467d8')   # Mac USB NIC
DST_MAC     = bytes.fromhex('54b56c26379f')   # TB10 Plus
SRC_IP      = '192.168.0.100'
DST_IP      = '192.168.0.10'
NOVASTAR_PORT = 5200

# --- macOS BPF ioctl constants ---
BIOCSETIF     = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN     = 0x40044266
BIOCSHDRCMPLT = 0x80044275


def open_bpf(iface: str) -> int:
    for i in range(256):
        try:
            fd = os.open(f'/dev/bpf{i}', os.O_RDWR)
            ifreq = struct.pack('16s', iface.encode())
            fcntl.ioctl(fd, BIOCSETIF, ifreq)
            fcntl.ioctl(fd, BIOCIMMEDIATE, struct.pack('I', 1))
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack('I', 1))  # send our own src MAC
            print(f'[BPF] opened /dev/bpf{i} on {iface}')
            return fd
        except OSError:
            continue
    raise RuntimeError('No BPF device available')


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def build_arp_reply(sender_ip: str, sender_mac: bytes, target_ip: str, target_mac: bytes) -> bytes:
    """Build an ARP reply frame."""
    ARP_ETYPE = b'\x08\x06'
    arp = struct.pack('!HHBBH',
        1,     # HTYPE: Ethernet
        0x0800, # PTYPE: IPv4
        6, 4,  # HLEN, PLEN
        2,     # OPER: reply
    )
    arp += sender_mac + socket.inet_aton(sender_ip)
    arp += target_mac + socket.inet_aton(target_ip)
    arp += b'\x00' * 18  # padding to 60 bytes
    eth = target_mac + sender_mac + ARP_ETYPE
    return eth + arp


def build_tcp_syn(src_port: int = 54321, dst_port: int = NOVASTAR_PORT, seq: int = 1000) -> bytes:
    """Build a TCP SYN frame."""
    src = socket.inet_aton(SRC_IP)
    dst = socket.inet_aton(DST_IP)
    # TCP header: sport, dport, seq, ack, offset+flags, window, cksum, urgent
    tcp_hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port,
        seq, 0,
        0x50, 0x02,  # data offset=5, SYN flag
        65535, 0, 0)
    pseudo = src + dst + b'\x00\x06' + struct.pack('!H', len(tcp_hdr))
    cksum = checksum(pseudo + tcp_hdr)
    tcp_hdr = tcp_hdr[:16] + struct.pack('!H', cksum) + tcp_hdr[18:]
    ip_len = 20 + len(tcp_hdr)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_len, 0, 0, 64, 6, 0, src, dst)
    ip_cksum = checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ip_cksum) + ip_hdr[12:]
    eth = DST_MAC + SRC_MAC + b'\x08\x00'
    return eth + ip_hdr + tcp_hdr


def build_tcp_data(payload: bytes, src_port: int, dst_port: int,
                   seq: int, ack: int, flags: int = 0x18) -> bytes:
    """Build a TCP data (ACK+PSH) frame."""
    src = socket.inet_aton(SRC_IP)
    dst = socket.inet_aton(DST_IP)
    tcp_hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port,
        seq, ack,
        0x50, flags,
        65535, 0, 0)
    pseudo = src + dst + b'\x00\x06' + struct.pack('!H', len(tcp_hdr) + len(payload))
    cksum = checksum(pseudo + tcp_hdr + payload)
    tcp_hdr = tcp_hdr[:16] + struct.pack('!H', cksum) + tcp_hdr[18:]
    ip_len = 20 + len(tcp_hdr) + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_len, 0, 0, 64, 6, 0, src, dst)
    ip_cksum = checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack('!H', ip_cksum) + ip_hdr[12:]
    eth = DST_MAC + SRC_MAC + b'\x08\x00'
    return eth + ip_hdr + tcp_hdr + payload


def build_novastar_packet(address: int, data: bytes, io_dir: int = 0x01, serial: int = 0) -> bytes:
    """
    Build a Novastar protocol packet.
    Packet layout (all multi-byte fields little-endian):
      [0-1]   55 AA      request header
      [2]     status     0x00
      [3]     serial_num
      [4]     source     0xFE = Computer
      [5]     dest       0xFF = broadcast
      [6]     dev_type   0x01 = ReceivingCard
      [7]     port       0xFF = all ports
      [8-9]   card_index 0xFFFF = all cards
      [10]    io_dir     0x01=write 0x00=read
      [11]    padding    0x00
      [12-15] address    uint32 LE
      [16-17] data_len   uint16 LE
      [18+]   data
      [-2,-1] checksum   uint16 LE = (sum of bytes 2..end-2) + 0x5555
    """
    header = bytes([
        0x55, 0xAA,          # magic
        0x00,                # status
        serial & 0xFF,       # serial
        0xFE,                # source: Computer
        0xFF,                # dest: broadcast
        0x01,                # device type: ReceivingCard
        0xFF,                # port: all
    ])
    header += struct.pack('<HBB', 0xFFFF, io_dir, 0x00)  # card_index, io_dir, padding
    header += struct.pack('<IH', address, len(data))      # address, data_len
    content = header[2:] + data
    cksum = (sum(content) + 0x5555) & 0xFFFF
    return header + data + struct.pack('<H', cksum)


# --- Novastar commands ---
COMMANDS = {
    'read_brightness': (0x02000001, b'', 0x00, 1),   # read GlobalBrightness (1 byte)
    'read_test_mode':  (0x02000101, b'', 0x00, 1),   # read SelfTestMode (1 byte)
    'read_kill_mode':  (0x02000100, b'', 0x00, 1),   # read KillMode (1 byte)
    'set_red':         (0x02000101, bytes([0x02]), 0x01, 0),  # write SelfTestMode = Red
    'set_green':       (0x02000101, bytes([0x03]), 0x01, 0),
    'set_blue':        (0x02000101, bytes([0x04]), 0x01, 0),
    'set_white':       (0x02000101, bytes([0x05]), 0x01, 0),
    'set_normal':      (0x02000101, bytes([0x00]), 0x01, 0),  # off / normal
}


def send_command(fd: int, name: str, serial: int = 0):
    addr, data, io_dir, read_len = COMMANDS[name]
    if io_dir == 0x00:  # read: payload is read_len zeros
        data = bytes(read_len)
    pkt = build_novastar_packet(addr, data, io_dir, serial)
    frame = build_udp_packet(pkt)
    os.write(fd, frame)
    print(f'[TX] {name}: {binascii.hexlify(pkt).decode()}')


def capture_thread(duration: int = 10):
    """Run tcpdump on en9 capturing to pcap while we probe."""
    out = os.path.expanduser('~/Desktop/novastar_probe.pcap')
    proc = subprocess.Popen(
        ['tcpdump', '-i', IFACE, '-s', '0', '-w', out, '--immediate-mode',
         'udp port 5200 or udp port 5201 or tcp port 5200'],
        stderr=subprocess.DEVNULL
    )
    time.sleep(duration)
    proc.terminate()
    proc.wait()
    print(f'[CAP] Saved capture to {out}')


if __name__ == '__main__':
    print('=== Novastar TB10 Plus Probe ===')
    print(f'Target: {DST_IP} ({":".join(f"{b:02x}" for b in DST_MAC)})')
    print(f'Source: {SRC_IP} ({":".join(f"{b:02x}" for b in SRC_MAC)})')
    print()

    # Start capture in background
    cap = threading.Thread(target=capture_thread, args=(15,), daemon=True)
    cap.start()
    time.sleep(0.5)

    # Open BPF
    fd = open_bpf(IFACE)

    serial = 0
    try:
        # 1. Read brightness and test mode
        for cmd in ['read_brightness', 'read_test_mode', 'read_kill_mode']:
            send_command(fd, cmd, serial)
            serial += 1
            time.sleep(0.5)

        print()
        print('[*] Cycling test patterns (watching for LED response)...')
        for cmd in ['set_red', 'set_green', 'set_blue', 'set_white', 'set_normal']:
            time.sleep(2)
            send_command(fd, cmd, serial)
            serial += 1

        print()
        print('[*] Waiting for capture to finish...')
        cap.join(timeout=20)

    finally:
        os.close(fd)

    print('[DONE] Open ~/Desktop/novastar_probe.pcap in Wireshark to analyze responses.')
