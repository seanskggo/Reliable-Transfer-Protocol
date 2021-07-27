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
from helper import *

##################################################################
# Functions
##################################################################

# Send TCP packet and log the send in a log file
# payload = [seq, ack, data, MSS, send_type, packet_type]
# data should be encoded
# send_type: snd etc
# packet_type: S, SA etc
# def send(client, addr, payload, empty):
#     seq, ack, data, MSS, s_type, p_type = decoder(payload)
#     serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
#     ttime = round((time.time() - EPOCH) * 1000, 3)
#     log.append([s_type, ttime, p_type, seq, ack, len(data)])
#     pkt = struct.pack(serial, *encoder([seq, ack, data, MSS, p_type]))
#     client.sendto(pkt, addr)

# Recieve TCP packet and log the send in a log file
# send_type: snd etc
# packet_type: S, SA etc
# def receive(client, MSS, empty):
#     msg, _ = client.recvfrom(MSS + HEADER_SIZE)
#     serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
#     seq, ack, data, MSS, p_type = decoder(struct.unpack(serial, msg))
#     ttime = round((time.time() - EPOCH) * 1000, 3)
#     log.append([Action.RECEIVE.value, ttime, p_type, seq, ack, len(data)])

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 9): exit(SENDER_ERROR)
try:
    ip, port, filename, MWS, MSS, timeout, pdrop, seed = (
        sys.argv[1], int(sys.argv[2]), 
        sys.argv[3], int(sys.argv[4]), 
        int(sys.argv[5]), int(sys.argv[6]), 
        float(sys.argv[7]), sys.argv[8], 
    )
except: exit(SENDER_ERROR)

# Basic error handling
if not 0 < pdrop < 1: exit(PDROP_ERROR)
if MSS <= 0: exit(MSS_ERROR)

# Create UDP socket client
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
log = list()

# Opening handshake -> no connection or teardown packets will be dropped
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.SYN.value], log, True)
receive(client, MSS, log, True)
send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.ACK.value], log, True)

# Open file for reading. If the file does not exist, throw error
with open(filename, "r") as file:
    packet = file.read(MSS)
    while packet:
        send(client, (ip, port), [0, 0, packet, MSS, Action.SEND.value, Packet.DATA.value], log, False)
        packet = file.read(MSS)
    # Initiate teardown -> no connection or teardown packets will be dropped
    send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.FIN.value], log, False)
    receive(client, MSS, log, True)
    send(client, (ip, port), [0, 0, Packet.NONE.value, MSS, Action.SEND.value, Packet.ACK.value], log, True)

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
