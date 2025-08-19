#!/usr/bin/env python3
#
# Helper script to generate a pcap file with a single HTTP request
# split across 5 packets that arrive in reverse order (requiring reassembly).

from scapy.all import IP, TCP, Raw, wrpcap
import os
import sys
import time


# Create packets for HTTP session with reordered request
packets = []

# TCP connection setup (3-way handshake)
client_ip = "192.168.1.100"
server_ip = "192.168.1.200"
client_port = 45678
server_port = 80

# SYN
syn = IP(src=client_ip, dst=server_ip) / TCP(
    sport=client_port, dport=server_port, flags="S", seq=1000
)
packets.append(syn)

# SYN-ACK
syn_ack = IP(src=server_ip, dst=client_ip) / TCP(
    sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001
)
packets.append(syn_ack)

# ACK
ack = IP(src=client_ip, dst=server_ip) / TCP(
    sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001
)
packets.append(ack)

# Set base timestamp for all packets
base_time = time.time()

# Set timestamps for handshake packets
syn.time = base_time + 0.001
syn_ack.time = base_time + 0.002
ack.time = base_time + 0.003

# HTTP request split across 5 parts
http_request_part1 = "GET /very/long/path/to/some/resource.html HTTP/1.1\r\n"
http_request_part2 = (
    "Host: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
)
http_request_part3 = (
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
)
http_request_part4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
http_request_part5 = "Accept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\n\r\n"

# Create the 5 request packets with correct sequence numbers
req_packets = []

# Packet 1 (first part)
req_packet1 = (
    IP(src=client_ip, dst=server_ip)
    / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
    / Raw(load=http_request_part1)
)
req_packet1.time = base_time + 0.008  # This packet arrives last (chronologically)
req_packets.append(req_packet1)

# Packet 2 (second part)
req_packet2 = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=1001 + len(http_request_part1),
        ack=2001,
    )
    / Raw(load=http_request_part2)
)
req_packet2.time = base_time + 0.007  # This packet arrives second-to-last
req_packets.append(req_packet2)

# Packet 3 (third part)
req_packet3 = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=1001 + len(http_request_part1) + len(http_request_part2),
        ack=2001,
    )
    / Raw(load=http_request_part3)
)
req_packet3.time = base_time + 0.006  # This packet arrives in the middle
req_packets.append(req_packet3)

# Packet 4 (fourth part)
req_packet4 = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="A",
        seq=1001
        + len(http_request_part1)
        + len(http_request_part2)
        + len(http_request_part3),
        ack=2001,
    )
    / Raw(load=http_request_part4)
)
req_packet4.time = base_time + 0.005  # This packet arrives second
req_packets.append(req_packet4)

# Packet 5 (fifth part, with PSH flag to indicate end of request)
req_packet5 = (
    IP(src=client_ip, dst=server_ip)
    / TCP(
        sport=client_port,
        dport=server_port,
        flags="PA",
        seq=1001
        + len(http_request_part1)
        + len(http_request_part2)
        + len(http_request_part3)
        + len(http_request_part4),
        ack=2001,
    )
    / Raw(load=http_request_part5)
)
req_packet5.time = base_time + 0.004  # This packet arrives first (chronologically)
req_packets.append(req_packet5)

# Add the request packets in REVERSE order (5, 4, 3, 2, 1) by sequence number
# but with timestamps showing they arrive in chronological order
for i in range(4, -1, -1):
    packets.append(req_packets[i])

# Write to pcap file
script_dir = os.path.dirname(sys.argv[0])
traces_dir = os.path.join(script_dir, "..", "Traces")
pcap_path = os.path.join(traces_dir, "http-reordered.pcap")
wrpcap(pcap_path, packets)
