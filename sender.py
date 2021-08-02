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

##################################################################
# Restart from here
##################################################################

# Opening handshake
client.sendto(encode(seq, ack, Packet.NONE, Packet.SYN), (ip, port))
add_log(Action.SEND, seq, ack, Packet.NONE, Packet.SYN)

msg, _ = client.recvfrom(2048)
seq, ack, data, packet_type = decode(msg)
add_log(Action.RECEIVE, seq, ack, data, packet_type)

client.sendto(encode(seq, ack, Packet.NONE, Packet.ACK), (ip, port))
add_log(Action.SEND, seq, ack, Packet.NONE, Packet.ACK)

# Open file for reading. If the file does not exist, throw error
with open(filename, "r") as file:
    packet = file.read(MSS)

    while packet:

        client.sendto(encode(seq, ack, packet, Packet.DATA), (ip, port))
        add_log(Action.SEND, seq, ack, packet, Packet.DATA)

        msg, _ = client.recvfrom(2048)
        seq, ack, data, packet_type = decode(msg)
        add_log(Action.RECEIVE, seq, ack, data, packet_type)
        
        packet = file.read(MSS)

    # Initiate teardown -> no connection or teardown packets will be dropped
    client.sendto(encode(seq, ack, Packet.NONE, Packet.FIN), (ip, port))
    add_log(Action.SEND, seq, ack, Packet.NONE, Packet.FIN)
    
    msg, _ = client.recvfrom(2048)
    seq, ack, data, packet_type = decode(msg)
    add_log(Action.RECEIVE, seq, ack, data, packet_type)

    client.sendto(encode(seq, ack, Packet.NONE, Packet.ACK), (ip, port))
    add_log(Action.SEND, seq, ack, Packet.NONE, Packet.ACK)

# Create log file
with open("Sender_log.txt", "w") as logfile:
    tot_data, num_seg, drp_pkt, re_seg, dup_ack = [0] * 5
    for a, b, c, d, e, f in get_log():
        if a == Action.SEND: tot_data += f
        if a == Action.SEND and c == Packet.DATA: num_seg += 1
        logfile.write(f"{a:<5} {b:<12} {c:<6} {d:<6} {f:<6} {e:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Transferred (bytes):  {tot_data}\n")
    logfile.write(f"No. Data Segments Sent:          {num_seg}\n")
    logfile.write(f"No. Packets Dropped:             {drp_pkt}\n")
    logfile.write(f"No. Retransmitted Segments:      {re_seg}\n")
    logfile.write(f"No. Duplicate Acknowledgements:  {dup_ack}\n")
