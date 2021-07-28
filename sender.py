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
import random
from helper import *

##################################################################
# Sender Functions
##################################################################

# PL Module for dropping segments
def PL_module(pdrop) -> bool:
    return True if random.random() > pdrop else False

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

# Set seed for PL module
random.seed(seed)

# Create UDP socket client
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.settimeout(timeout/1000)
log = list()

# Opening handshake -> no connection or teardown packets will be dropped
send(client, (ip, port), [0, 0, Packet.NONE, MSS, Action.SEND, Packet.SYN], log, True)
receive(client, MSS, log, True)
send(client, (ip, port), [0, 0, Packet.NONE, MSS, Action.SEND, Packet.ACK], log, True)

# Open file for reading. If the file does not exist, throw error
with open(filename, "r") as file:
    packet = file.read(MSS)
    while packet:
        if PL_module(pdrop): 
            send(client, (ip, port), [0, 0, packet, MSS, Action.SEND, Packet.DATA], log, False)
        receive(client, MSS, log, True)
        packet = file.read(MSS)
    # Initiate teardown -> no connection or teardown packets will be dropped
    send(client, (ip, port), [0, 0, Packet.NONE, MSS, Action.SEND, Packet.FIN], log, False)
    receive(client, MSS, log, True)
    send(client, (ip, port), [0, 0, Packet.NONE, MSS, Action.SEND, Packet.ACK], log, True)

# Create log file
with open("Sender_log.txt", "w") as logfile:
    tot_data, num_seg, drp_pkt, re_seg, dup_ack = [0] * 5
    for a, b, c, d, e, f in log:
        if a == Action.SEND: tot_data += f
        if a == Action.SEND and c == Packet.DATA: num_seg += 1
        logfile.write(f"{a:<5} {b:<8} {c:<6} {d:<6} {e:<6} {f:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Transferred (bytes):  {tot_data}\n")
    logfile.write(f"No. Data Segments Sent:          {num_seg}\n")
    logfile.write(f"No. Packets Dropped:             {drp_pkt}\n")
    logfile.write(f"No. Retransmitted Segments:      {re_seg}\n")
    logfile.write(f"No. Duplicate Acknowledgements:  {dup_ack}\n")
