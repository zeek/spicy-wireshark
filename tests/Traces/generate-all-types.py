#!/usr/bin/env python3
#
# Helper script to (re)-generate the pcap file for the test wireshark/all-types.spicy.

from scapy.all import *
import struct
import os
import sys

# Create the payload that matches the Types grammar structure
payload = b""

# a: bytes &size=5;
payload += b"ABCDE"

# b: int16;
payload += struct.pack(">h", 12345)  # signed 16-bit: 12345

# c: int32; 
payload += struct.pack(">i", 987654321)  # signed 32-bit: 987654321

# d: int64;
payload += struct.pack(">q", 1234567890123456789)  # signed 64-bit: large number

# e: int8;
payload += struct.pack(">b", 42)  # signed 8-bit: 42

# f: uint16;
payload += struct.pack(">H", 65000)  # unsigned 16-bit: 65000

# g: uint32;
payload += struct.pack(">I", 4000000000)  # unsigned 32-bit: 4 billion

# h: uint64;
payload += struct.pack(">Q", 18000000000000000000)  # unsigned 64-bit: huge number

# i: uint8;
payload += struct.pack(">B", 255)  # unsigned 8-bit: 255

# j through r: bytes &size=1 &convert=... (these just need 1 byte each)
# The actual byte value doesn't matter since they get converted
payload += b"j"  # j: converts to 3.14
payload += b"k"  # k: converts to 1.2.3.4
payload += b"l"  # l: converts to [2001:0db8::1428:57ab]
payload += b"m"  # m: converts to True
payload += b"n"  # n: converts to "MyStröng"
payload += b"o"  # o: converts to time(1617238923)
payload += b"p"  # p: converts to 80/tcp
payload += b"q"  # q: converts to interval(4.0)
payload += b"r"  # r: converts to MyEnum(2)

# s: MyBitfield;
payload += struct.pack(">B", 0b10101010)  # MyBitfield: 8 bits with alternating bits set (dec 170)

# anonymous 16-bit bitfield
payload += struct.pack(">H", 0xffff)  # anonymous 16-bit bitfield

# Create UDP packet
packet = IP(src="192.168.1.100", dst="192.168.1.200") / UDP(sport=12345, dport=8888) / Raw(load=payload)

# Write to pcap file
# Derive path to Traces directory from script location
script_dir = os.path.dirname(sys.argv[0])
traces_dir = os.path.join(script_dir, "..", "Traces")
pcap_path = os.path.join(traces_dir, "all-types.pcap")
wrpcap(pcap_path, packet)
