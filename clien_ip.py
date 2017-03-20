from socket import socket
from socket import AF_INET
from socket import SOCK_STREAM
from socket import SOL_SOCKET
from socket import SO_REUSEADDR
import time
from datetime import datetime
import sys
from hdlc import read_hdlc
from sources.ebilockcmain import Edilock as ebl

status = True
hdlc_list = []
s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.connect(('192.168.101.100', 4016))
count = 10
while status:
    #datetime.fromtimestamp()
    hdlc_list.append((s.recv(4096)))
    t = time.time()
    print("Time: {}\n DATA: {}".format(time.ctime(t), ebl.from_hdlc(read_hdlc(s.recv(4096))).check_telegramm()))
    #print(s.recv(4096))
    #time.sleep()
    count -= 1
    if count == 0:
        status = False

