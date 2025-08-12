#!/usr/bin/env python3
#
# Helper script to generate a pcap file with TFTP packets for each opcode defined in RFC 1350.

from scapy.all import *
import struct
import os
import sys

packets = []

# TFTP server and client addresses
client_ip = "192.168.1.100"
server_ip = "192.168.1.200"
client_port = 12345
server_port = 69

# 1. RRQ (Read Request) - opcode 1
# Format: opcode(2) + filename + 0 + mode + 0
rrq_payload = struct.pack(">H", 1)  # opcode 1
rrq_payload += b"test.txt\x00"      # filename + null terminator
rrq_payload += b"octet\x00"         # mode + null terminator

rrq_packet = IP(src=client_ip, dst=server_ip) / UDP(sport=client_port, dport=server_port) / Raw(load=rrq_payload)
packets.append(rrq_packet)

# 2. WRQ (Write Request) - opcode 2  
# Format: opcode(2) + filename + 0 + mode + 0
wrq_payload = struct.pack(">H", 2)  # opcode 2
wrq_payload += b"upload.txt\x00"    # filename + null terminator
wrq_payload += b"octet\x00"         # mode + null terminator

wrq_packet = IP(src=client_ip, dst=server_ip) / UDP(sport=client_port, dport=server_port) / Raw(load=wrq_payload)
packets.append(wrq_packet)

# 3. DATA - opcode 3
# Format: opcode(2) + block#(2) + data
data_payload = struct.pack(">H", 3)  # opcode 3
data_payload += struct.pack(">H", 1) # block number 1
data_payload += b"Hello TFTP World!" # actual data

data_packet = IP(src=server_ip, dst=client_ip) / UDP(sport=server_port, dport=client_port) / Raw(load=data_payload)
packets.append(data_packet)

# 4. ACK (Acknowledgment) - opcode 4
# Format: opcode(2) + block#(2)
ack_payload = struct.pack(">H", 4)  # opcode 4
ack_payload += struct.pack(">H", 1) # block number 1

ack_packet = IP(src=client_ip, dst=server_ip) / UDP(sport=client_port, dport=server_port) / Raw(load=ack_payload)
packets.append(ack_packet)

# 5. ERROR - opcode 5
# Format: opcode(2) + error_code(2) + error_msg + 0
error_payload = struct.pack(">H", 5)  # opcode 5
error_payload += struct.pack(">H", 1) # error code 1 (File not found)
error_payload += b"File not found\x00" # error message + null terminator

error_packet = IP(src=server_ip, dst=client_ip) / UDP(sport=server_port, dport=client_port) / Raw(load=error_payload)
packets.append(error_packet)

# Write all packets to pcap file
# Derive path to Traces directory from script location
script_dir = os.path.dirname(sys.argv[0])
traces_dir = os.path.join(script_dir, "..", "Traces")
pcap_path = os.path.join(traces_dir, "tftp.pcap")
wrpcap(pcap_path, packets)
