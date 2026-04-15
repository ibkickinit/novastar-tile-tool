#!/usr/bin/env python3
"""
Extract AVON/BVON packets from the Viplex capture and print their exact bytes.
Also attempts to decode the JSON payload and identify the session/auth token.
"""

import sys
import struct
import socket

try:
    from scapy.all import rdpcap, UDP, IP, Raw
except ImportError:
    print("ERROR: scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

PCAP = '/Users/jedgerly/Desktop/viplex_capture.pcapng'

pkts = rdpcap(PCAP)
print(f"Loaded {len(pkts)} packets from {PCAP}\n")

avon_pkts = []
bvon_pkts = []
all_udp = []

for pkt in pkts:
    if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
        continue
    sport = pkt[UDP].sport
    dport = pkt[UDP].dport
    all_udp.append((sport, dport, pkt[IP].src, pkt[IP].dst))
    if not pkt.haslayer(Raw):
        continue
    payload = bytes(pkt[Raw])
    if payload[:4] == b'AVON':
        avon_pkts.append((pkt[IP].src, pkt[IP].dst, sport, dport, payload))
    elif payload[:4] == b'BVON':
        bvon_pkts.append((pkt[IP].src, pkt[IP].dst, sport, dport, payload))

print(f"Found {len(avon_pkts)} AVON packets and {len(bvon_pkts)} BVON packets")
print()

# Print all unique UDP port pairs for reference
seen_ports = set()
for sport, dport, src, dst in all_udp:
    key = (sport, dport)
    if key not in seen_ports:
        seen_ports.add(key)
        print(f"  UDP {src}:{sport} → {dst}:{dport}")
print()

for i, (src, dst, sport, dport, payload) in enumerate(avon_pkts):
    print(f"=== AVON #{i+1}: {src}:{sport} → {dst}:{dport} ({len(payload)} bytes) ===")
    print(f"  hex: {payload.hex()}")
    print(f"  raw: {payload}")
    print()

for i, (src, dst, sport, dport, payload) in enumerate(bvon_pkts):
    print(f"=== BVON #{i+1}: {src}:{sport} → {dst}:{dport} ({len(payload)} bytes) ===")
    print(f"  hex: {payload.hex()}")
    # Try to decode JSON portion
    # BVON header is typically fixed bytes before JSON
    # Find '{' character
    json_start = payload.find(b'{')
    if json_start >= 0:
        print(f"  header bytes: {payload[:json_start].hex()}")
        try:
            import json
            json_str = payload[json_start:].decode('utf-8', errors='replace')
            parsed = json.loads(json_str)
            print(f"  JSON: {json.dumps(parsed, indent=4)}")
        except Exception as e:
            print(f"  raw after header: {payload[json_start:]}")
    print()
