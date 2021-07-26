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

# Send TCP packet and log the send in a log file
# payload = [seq, ack, data, MSS, send_type, packet_type]
# data should be encoded
# send_type: snd etc
# packet_type: S, SA etc
def send(server, addr, payload, empty):
    seq, ack, data, MSS, s_type, p_type = payload
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    pkt = struct.pack(serial, seq, ack, data, MSS, p_type.encode(),)
    server.sendto(pkt, addr)

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

# Opening handshake -> no connection or teardown packets will be dropped
msg, addr = server.recvfrom(header_size)
seq, ack, data, MSS, p_type = struct.unpack("!II0sI2s", msg)
send(server, addr, [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.SYNACK.value], True)
msg, addr = server.recvfrom(MSS + header_size)

# Open and write to file until teardown
with open(filename, "wb") as file:
    while True:
        msg, addr = server.recvfrom(MSS + header_size)
        # Handle teardown -> no connection or teardown packets will be dropped
        seq, ack, data, MSS, p_type = struct.unpack(f"!II{MSS}sI2s", msg)
        if p_type.strip(b'\x00').decode() == Packet.FIN.value:
            send(server, addr, [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.FINACK.value], False)
            break
        else: file.write(msg)

##################################################################
# Test Command
##################################################################

# Linux

# python3 receiver.py 8000 FileReceived.txt

# Powershell

# python receiver.py 8000 FileReceived.txt
