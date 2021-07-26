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
import struct
import time
import enum

##################################################################
# Constants
##################################################################

error = (
    'USAGE: python sender.py receiver_host_ip receiver_port '
    + 'FileToSend.txt MWS MSS timeout pdrop seed'
)
pdrop_error = 'Pdrop parameter must be between 0 and 1'
MSS_error = 'Maximum Segment Size must be greater than 0'
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

# # Create TCP segment using struct (header is 18 bytes)
# def create_ptp_segment(flag, seq, ack, data, MSS):
#     return struct.pack(f"!2sIII{MSS}s", 
#         flag.encode(), seq, MSS, ack, data
#     )

# # Send TCP packet and log the send in a log file
# def send(client, addr, ptype, payload):
#     ttime = round((time.time() - epoch) * 1000, 3)
#     log.append([ptype, ttime, *payload[1:-1]])
#     client.sendto(create_ptp_segment(*payload), addr)

# Send TCP packet and log the send in a log file
# payload = [seq, ack, data, MSS, send_type, packet_type]
# data should be encoded
# send_type: snd etc
# packet_type: S, SA etc
def send(client, addr, payload, empty):
    seq, ack, data, MSS, s_type, p_type = payload
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    pkt = struct.pack(serial, seq, ack, data, MSS, p_type.encode())
    client.sendto(pkt, addr)

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 9): exit(error)
try:
    ip, port, filename, MWS, MSS, timeout, pdrop, seed = (
        sys.argv[1], int(sys.argv[2]), 
        sys.argv[3], int(sys.argv[4]), 
        int(sys.argv[5]), int(sys.argv[6]), 
        float(sys.argv[7]), sys.argv[8], 
    )
except: exit(error)

# Basic error handling
if not 0 < pdrop < 1: exit(pdrop_error)
if MSS <= 0: exit(MSS_error)

# Create UDP socket client
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Opening handshake -> no connection or teardown packets will be
# dropped
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.SYN.value], True)
msg, addr = client.recvfrom(MSS + header_size)
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.ACK.value], True)

# Open file for reading. If the file does not exist, throw error
# with open(filename, "rb") as file:
#     packet = file.read(MSS)
#     while packet:
#         send(client, (ip, port), Action.SEND.value, [Packet.ACK.value, 0, MSS, 0, packet])
#         packet = file.read(MSS)
#     # Initiate teardown -> no connection or teardown packets will be dropped
#     send(client, (ip, port), Action.SEND.value, [Packet.FIN.value, 0, 0, Packet.NONE.value, MSS])
#     msg, addr = client.recvfrom(MSS + header_size)
#     send(client, (ip, port), Action.SEND.value, [Packet.ACK.value, 0, 0, Packet.NONE.value, MSS])

# # Create log file
# with open("Sender_log.txt", "w") as logfile:
#     for a, b, c, d, e in log:
#         logfile.write(f"{a:<5} {b:<8} {c:<6} {d:<6} {e:<6}\n")

##################################################################
# Test Command
##################################################################

# Linux

# python3 sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1

# Powershell

# python sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1
