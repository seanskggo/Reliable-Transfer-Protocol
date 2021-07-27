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
from helper import encoder, decoder

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
def send(client, addr, payload, empty):
    seq, ack, data, MSS, s_type, p_type = decoder(payload)
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    pkt = struct.pack(serial, *encoder([seq, ack, data, MSS, p_type]))
    client.sendto(pkt, addr)

# Recieve TCP packet and log the send in a log file
# send_type: snd etc
# packet_type: S, SA etc
def receive(client, MSS, empty):
    msg, _ = client.recvfrom(MSS + header_size)
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    seq, ack, data, MSS, p_type = decoder(struct.unpack(serial, msg))
    ttime = round((time.time() - epoch) * 1000, 3)
    log.append([Action.RECEIVE.value, ttime, p_type, seq, ack, len(data)])

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

# Opening handshake -> no connection or teardown packets will be dropped
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.SYN.value], True)
receive(client, MSS, True)
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.ACK.value], True)

# Open file for reading. If the file does not exist, throw error
with open(filename, "r") as file:
    packet = file.read(MSS)
    while packet:
        send(client, (ip, port), [0, 0, packet, MSS, Action.SEND.value, Packet.DATA.value], False)
        packet = file.read(MSS)
    # Initiate teardown -> no connection or teardown packets will be dropped
    send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.FIN.value], False)
    receive(client, MSS, True)
    send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.ACK.value], False)

# Create log file
with open("Sender_log.txt", "w") as logfile:
    tot_data, num_seg, drp_pkt, re_seg, dup_ack = [0] * 5
    for a, b, c, d, e, f in log:
        if a == Action.SEND.value: tot_data += f
        if a == Action.SEND.value and c == Packet.DATA.value: num_seg += 1
        logfile.write(f"{a:<5} {b:<8} {c:<6} {d:<6} {e:<6} {f:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Transferred (bytes):  {tot_data}\n")
    logfile.write(f"No. Data Segments Sent:          {num_seg}\n")
    logfile.write(f"No. Packets Dropped:             {drp_pkt}\n")
    logfile.write(f"No. Retransmitted Segments:      {re_seg}\n")
    logfile.write(f"No. Duplicate Acknowledgements:  {dup_ack}\n")

##################################################################
# Test Command
##################################################################

# Linux

# python3 sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1

# Powershell

# python sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1
