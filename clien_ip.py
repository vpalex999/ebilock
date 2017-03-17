from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOL_SOCKET
from socket import SO_REUSEADDR
import time
import sys

status = True

s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.connect(('192.168.101.100', 4015))

while status:
    count = 100
    print(s.recv(4096))
    time.sleep(0.05)
    count -= 1
    if count == 0:
        status = False



