"""A resolver that answers A queries (10.99.2.2 for every name) and never answers AAAA: the AAAA blackhole."""
import socket
import struct
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 53))
while True:
    msg, peer = s.recvfrom(512)
    if len(msg) < 12:
        continue
    i = 12
    while i < len(msg) and msg[i] != 0:
        i += msg[i] + 1
    qend = i + 5
    qtype = struct.unpack("!H", msg[i + 1:i + 3])[0]
    if qtype != 1:
        continue  # AAAA and the rest: dropped
    header = msg[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("10.99.2.2")
    s.sendto(header + msg[12:qend] + answer, peer)
