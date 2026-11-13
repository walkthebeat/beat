"""A server that listens with a backlog of 1 and never accepts: its accept queue fills, further SYNs are dropped."""
import socket
import sys
import time

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(1)
time.sleep(60)
