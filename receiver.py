##################################################################
# COMP3331/9331 Computer Networks and Applications 
# Assignment 2 | Term 2, 2021
# By Sean Go (z5310199)
#
# >>> Python Verion Used: 3.8.5
##################################################################

##################################################################
# Imports
##################################################################

import sys
import socket
import time
import struct

##################################################################
# Constants
##################################################################

error = 'USAGE: python receiver.py receiver_port FileReceiverd.txt'
ip = '127.0.0.1'
log = list()
epoch = time.time()

##################################################################
# Functions
##################################################################

def create_ptp_segment(flag, seq, MSS, ack, data):
    length = len(data.encode())
    return struct.pack(f"!6sIII{length}s", 
        flag.encode(), seq, MSS, ack, data.encode()
    )

def send(server, addr, ptype, payload):
    ttime = round(time.time() - epoch, 3)
    log.append([ptype, ttime, *payload[1:-1]])
    server.sendto(create_ptp_segment(*payload), addr)

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(error)
try: port, filename, MSS = int(sys.argv[1]), sys.argv[2], 0
except: exit(error)

# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((ip, port))

# Opening handshake
msg, addr = server.recvfrom(2048)
_, _, MSS, _, _ = struct.unpack("!6sIII0s", msg)
send(server, addr, "snd", ["SYNACK", 0, 0, 0, ""])
msg, addr = server.recvfrom(2048)
print("done")
# Open and write to file until teardown
# with open(filename, "wb") as file:
#     while True:
#         msg, addr = server.recvfrom(2048) # Change buffer size -> SYN then get buffer size from header
#         file.write(msg)

##################################################################
# Test Command
##################################################################

# Linux

# python3 receiver.py 8000 FileReceived.txt

# Powershell

# python receiver.py 8000 FileReceived.txt
