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
from helper import encoder, decoder

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
    NONE = ""

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
    pkt = struct.pack(serial, *encoder([seq, ack, data, MSS, p_type]))
    server.sendto(pkt, addr)

# Recieve TCP packet and log the send in a log file
# send_type: snd etc
# packet_type: S, SA etc
def receive(server, MSS, empty):
    msg, addr = server.recvfrom(MSS + header_size)
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    seq, ack, data, MSS, p_type = decoder(struct.unpack(serial, msg))
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([Action.RECEIVE.value, ttime, p_type, seq, ack, len(data)])
    return ((seq, ack, data, MSS, p_type), addr)

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

# Opening handshake -> no connection or teardown packets will be dropped
# Received and sets the MSS for the TCP connection
(_, _, _, MSS, _), addr = receive(server, MSS, True)
send(server, addr, [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.SYNACK.value], True)
receive(server, MSS, True)

# Open and write to file until teardown
with open(filename, "w") as file:
    while True:
        (seq, ack, data, MSS, p_type), addr = receive(server, MSS, False)
        # Handle teardown -> no connection or teardown packets will be dropped
        if p_type == Packet.FIN.value:
            send(server, addr, [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.FINACK.value], True)
            break
        file.write(data)

# Create log file
with open("Receiver_log.txt", "w") as logfile:
    tot_data, num_seg, num_dup = [0] * 3
    for a, b, c, d, e, f in log:
        if a == Action.SEND.value: tot_data += f
        if a == Action.SEND.value and c == Packet.DATA.value: num_seg += 1
        logfile.write(f"{a:<5} {b:<8} {c:<6} {d:<6} {e:<6} {f:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Received (bytes):     {tot_data}\n")
    logfile.write(f"No. Data Segments Received:      {num_seg}\n")
    logfile.write(f"No. Duplicate Segments:          {num_dup}\n")

##################################################################
# Test Command
##################################################################

# Linux

# python3 receiver.py 8000 FileReceived.txt

# Powershell

# python receiver.py 8000 FileReceived.txt
