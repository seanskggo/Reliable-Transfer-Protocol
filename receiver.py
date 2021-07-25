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
import enum

##################################################################
# Constants and Classes
##################################################################

error = 'USAGE: python receiver.py receiver_port FileReceiverd.txt'
ip = '127.0.0.1'
log = list()
epoch = time.time()
header_size = 14

class Packet (enum.Enum):
    SYN = "S"
    ACK = "A"
    DATA = "D"
    SYNACK = "SA"
    FIN = "F"
    FINACK = "FA"
    NONE = "".encode()

class Action (enum.Enum):
    SEND = "snd"
    RECEIVE = "rcv"
    DROP = "drop"

##################################################################
# Functions
##################################################################

# Create TCP segment using struct (header is 18 bytes)
def create_ptp_segment(flag, seq, MSS, ack, data):
    return struct.pack(f"!2sIII{MSS}s", 
        flag.encode(), seq, MSS, ack, data
    )

# Send TCP packet and log the send in a log file
def send(server, addr, ptype, payload):
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([ptype, ttime, *payload[1:-1]])
    server.sendto(create_ptp_segment(*payload), addr)

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(error)
try: port, filename = int(sys.argv[1]), sys.argv[2]
except: exit(error)

# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((ip, port))

# Opening handshake -> no connection or teardown packets will be
# dropped
msg, addr = server.recvfrom(header_size)
_, _, MSS, _, _ = struct.unpack("!2sIII0s", msg)
send(server, addr, Action.SEND.value, [Packet.SYNACK.value, 0, 0, 0, Packet.NONE.value])
msg, addr = server.recvfrom(MSS + header_size)

# Open and write to file until teardown
with open(filename, "wb") as file:
    while True:
        msg, addr = server.recvfrom(MSS + header_size)
        # Handle teardown -> no connection or teardown packets will be dropped
        try: flag, seq, MSS, ack, data = struct.unpack("!2sIII0s", msg) 
        except: flag, seq, MSS, ack, data = struct.unpack(f"!2sIII{MSS}s", msg)
        if flag.strip(b'\x00').decode() == Packet.FIN.value:
            send(server, addr, Action.SEND.value, [Packet.FINACK.value, 0, 0, 0, Packet.NONE.value])
            break
        else: file.write(msg)

##################################################################
# Test Command
##################################################################

# Linux

# python3 receiver.py 8000 FileReceived.txt

# Powershell

# python receiver.py 8000 FileReceived.txt
