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
from helper import *

##################################################################
# Constants
##################################################################

SENDER_ERROR = \
    'USAGE: python sender.py receiver_host_ip receiver_port ' \
    + 'FileToSend.txt MWS MSS timeout pdrop seed'
PDROP_ERROR = 'Pdrop parameter must be between 0 and 1'
MSS_ERROR = 'Maximum Segment Size must be greater than 0'

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

# Set initial sequence number and ack
seq, ack = 121, 0

# Create UDP socket client
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(timeout/1000)
sender = Sender(client, (ip, port), MSS, MWS, seq, ack)
sender.set_PL_module(seed, pdrop)

# Opening handshake -> no connection or teardown packets will be dropped
sender.send_opening(Packet.SYN)
sender.receive()
sender.send(Packet.NONE, Packet.ACK)

# Open file for reading. If the file does not exist, throw error
with open(filename, "r") as file:
    packet = file.read(MSS)
    while packet:
        sender.send(packet, Packet.DATA)
        sender.receive()
        packet = file.read(MSS)
    # Initiate teardown -> no connection or teardown packets will be dropped
    sender.send(Packet.NONE, Packet.FIN)
    sender.receive()
    sender.send(Packet.NONE, Packet.ACK)

# Create log file
with open("Sender_log.txt", "w") as logfile:
    tot_data, num_seg, drp_pkt, re_seg, dup_ack = [0] * 5
    for a, b, c, d, e, f in sender.get_log():
        if a == Action.SEND: tot_data += f
        if a == Action.SEND and c == Packet.DATA: num_seg += 1
        logfile.write(f"{a:<5} {b:<12} {c:<6} {d:<6} {f:<6} {e:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Transferred (bytes):  {tot_data}\n")
    logfile.write(f"No. Data Segments Sent:          {num_seg}\n")
    logfile.write(f"No. Packets Dropped:             {drp_pkt}\n")
    logfile.write(f"No. Retransmitted Segments:      {re_seg}\n")
    logfile.write(f"No. Duplicate Acknowledgements:  {dup_ack}\n")

##################################################################
# Important Ideas
##################################################################

# def send_packet():
#     global seq, ack
#     if PL_module(pdrop): 
#         send(client, (ip, port), [seq, ack, packet, MSS, Action.SEND, Packet.DATA], log, False)
#     else: send(client, (ip, port), [seq, ack, packet, MSS, Action.DROP, Packet.DATA], log, False)
#     ack, seq = receive(client, MSS, log, True)[0][0:2]
# def check_timeout():
#     try: send_packet()
#     except: check_timeout()
# while packet:
#     check_timeout()
#     packet = file.read(MSS)

##################################################################
# Ideas
##################################################################

# def check_timeout(action):
#     try: 
#         if PL_module(pdrop): 
#             send(client, (ip, port), [0, 0, packet, MSS, action, Packet.DATA], log, False)
#         receive(client, MSS, log, True)
#     except: check_timeout(Action.DROP)
# check_timeout(Action.SEND)

# send(client, (ip, port), [seq, ack, packet, MSS, Action.SEND, Packet.DATA], log, False)
# ack, seq = receive(client, MSS, log, True)[0][0:2]