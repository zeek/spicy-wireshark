#!/usr/bin/env python3
from scapy.all import IP, UDP, Raw, wrpcap
import os
import sys
import time

# Prepare packet list
packets = []

client_ip = "192.168.1.100"
server_ip = "192.168.1.200"
client_port = 12345  # arbitrary ephemeral client port
server_port = 7  # Echo protocol port

payload = b"Hello, Spicy World!"

base_time = time.time()

# Client -> Server
c2s = (
    IP(src=client_ip, dst=server_ip)
    / UDP(sport=client_port, dport=server_port)
    / Raw(load=payload)
)
c2s.time = base_time

# Server -> Client
s2c = (
    IP(src=server_ip, dst=client_ip)
    / UDP(sport=server_port, dport=client_port)
    / Raw(load=payload)
)
s2c.time = base_time + 0.001

packets.extend([c2s, s2c])

script_dir = os.path.dirname(sys.argv[0])
traces_dir = os.path.join(script_dir, "..", "Traces")
pcap_path = os.path.join(traces_dir, "echo.pcap")

os.makedirs(traces_dir, exist_ok=True)
wrpcap(pcap_path, packets)
print(f"Wrote {pcap_path} with {len(packets)} packets.")
