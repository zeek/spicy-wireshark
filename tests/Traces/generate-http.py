#!/usr/bin/env python3
#
# Helper script to generate a pcap file with a single HTTP session containing
# two requests with their replies.

from scapy.all import *
import os
import sys

# Create packets for a complete HTTP session
packets = []

# TCP connection setup (3-way handshake)
client_ip = "192.168.1.100"
server_ip = "192.168.1.200"
client_port = 45678
server_port = 80

# SYN
syn = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="S", seq=1000)
packets.append(syn)

# SYN-ACK
syn_ack = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="SA", seq=2000, ack=1001)
packets.append(syn_ack)

# ACK
ack = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001)
packets.append(ack)

# First HTTP request (split across 3 packets)
http_request1_part1 = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
http_request1_part2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
http_request1_part3 = "Accept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\n\r\n"

req1_packet1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001, ack=2001) / Raw(load=http_request1_part1)
packets.append(req1_packet1)

req1_packet2 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001+len(http_request1_part1), ack=2001) / Raw(load=http_request1_part2)
packets.append(req1_packet2)

req1_packet3 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001+len(http_request1_part1)+len(http_request1_part2), ack=2001) / Raw(load=http_request1_part3)
packets.append(req1_packet3)

http_request1 = http_request1_part1 + http_request1_part2 + http_request1_part3

# ACK for first request
ack1 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001, ack=1001+len(http_request1))
packets.append(ack1)

# First HTTP response
http_body1 = (
    "<html>\r\n"
    "<head><title>Welcome</title></head>\r\n"
    "<body>\r\n"
    "<h1>Hello World!</h1>\r\n"
    "<p>This is the first page.</p>\r\n"
    "</body>\r\n"
    "</html>\r\n"
)

http_response1 = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Mon, 01 Apr 2024 12:00:00 GMT\r\n"
    "Server: Apache/2.4.41\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    f"Content-Length: {len(http_body1)}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
) + http_body1

# Split first HTTP response across 3 packets
http_response1_headers = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Mon, 01 Apr 2024 12:00:00 GMT\r\n"
    "Server: Apache/2.4.41\r\n"
)
http_response1_headers2 = (
    "Content-Type: text/html; charset=UTF-8\r\n"
    f"Content-Length: {len(http_body1)}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)
http_response1_body = http_body1

resp1_packet1 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001, ack=1001+len(http_request1)) / Raw(load=http_response1_headers)
packets.append(resp1_packet1)

resp1_packet2 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001+len(http_response1_headers), ack=1001+len(http_request1)) / Raw(load=http_response1_headers2)
packets.append(resp1_packet2)

resp1_packet3 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001+len(http_response1_headers)+len(http_response1_headers2), ack=1001+len(http_request1)) / Raw(load=http_response1_body)
packets.append(resp1_packet3)

http_response1 = http_response1_headers + http_response1_headers2 + http_response1_body

# ACK for first response
ack2 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001+len(http_request1), ack=2001+len(http_response1))
packets.append(ack2)

# Second HTTP request
http_request2 = (
    "GET /about.html HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
    "Accept-Language: en-US,en;q=0.5\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)

# Second HTTP request (split across 3 packets)
http_request2_part1 = "GET /about.html HTTP/1.1\r\nHost: example.com\r\n"
http_request2_part2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
http_request2_part3 = "Accept-Language: en-US,en;q=0.5\r\nConnection: keep-alive\r\n\r\n"

req2_packet1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001+len(http_request1), ack=2001+len(http_response1)) / Raw(load=http_request2_part1)
packets.append(req2_packet1)

req2_packet2 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001+len(http_request1)+len(http_request2_part1), ack=2001+len(http_response1)) / Raw(load=http_request2_part2)
packets.append(req2_packet2)

req2_packet3 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="PA", seq=1001+len(http_request1)+len(http_request2_part1)+len(http_request2_part2), ack=2001+len(http_response1)) / Raw(load=http_request2_part3)
packets.append(req2_packet3)

http_request2 = http_request2_part1 + http_request2_part2 + http_request2_part3

# ACK for second request
ack3 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001+len(http_response1), ack=1001+len(http_request1)+len(http_request2))
packets.append(ack3)

# Second HTTP response
http_body2 = (
    "<html>\r\n"
    "<head><title>About</title></head>\r\n"
    "<body>\r\n"
    "<h1>About Us</h1>\r\n"
    "<p>This is the about page.</p>\r\n"
    "</body>\r\n"
    "</html>\r\n"
)

http_response2 = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Mon, 01 Apr 2024 12:00:05 GMT\r\n"
    "Server: Apache/2.4.41\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    f"Content-Length: {len(http_body2)}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
) + http_body2

# Split second HTTP response across 3 packets
http_response2_headers = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Mon, 01 Apr 2024 12:00:05 GMT\r\n"
    "Server: Apache/2.4.41\r\n"
)
http_response2_headers2 = (
    "Content-Type: text/html; charset=UTF-8\r\n"
    f"Content-Length: {len(http_body2)}\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
)
http_response2_body = http_body2

resp2_packet1 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001+len(http_response1), ack=1001+len(http_request1)+len(http_request2)) / Raw(load=http_response2_headers)
packets.append(resp2_packet1)

resp2_packet2 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="A", seq=2001+len(http_response1)+len(http_response2_headers), ack=1001+len(http_request1)+len(http_request2)) / Raw(load=http_response2_headers2)
packets.append(resp2_packet2)

resp2_packet3 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="PA", seq=2001+len(http_response1)+len(http_response2_headers)+len(http_response2_headers2), ack=1001+len(http_request1)+len(http_request2)) / Raw(load=http_response2_body)
packets.append(resp2_packet3)

http_response2 = http_response2_headers + http_response2_headers2 + http_response2_body

# ACK for second response
ack4 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1001+len(http_request1)+len(http_request2), ack=2001+len(http_response1)+len(http_response2))
packets.append(ack4)

# TCP connection teardown (FIN handshake)
fin1 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="FA", seq=1001+len(http_request1)+len(http_request2), ack=2001+len(http_response1)+len(http_response2))
packets.append(fin1)

fin_ack1 = IP(src=server_ip, dst=client_ip) / TCP(sport=server_port, dport=client_port, flags="FA", seq=2001+len(http_response1)+len(http_response2), ack=1002+len(http_request1)+len(http_request2))
packets.append(fin_ack1)

fin_ack2 = IP(src=client_ip, dst=server_ip) / TCP(sport=client_port, dport=server_port, flags="A", seq=1002+len(http_request1)+len(http_request2), ack=2002+len(http_response1)+len(http_response2))
packets.append(fin_ack2)

# Write to pcap file
# Derive path to Traces directory from script location
script_dir = os.path.dirname(sys.argv[0])
traces_dir = os.path.join(script_dir, "..", "Traces")
pcap_path = os.path.join(traces_dir, "http.pcap")
wrpcap(pcap_path, packets)
