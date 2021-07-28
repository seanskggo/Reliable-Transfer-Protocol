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
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(RECEIVER_ERROR)
try: port, filename, MSS = int(sys.argv[1]), sys.argv[2], 0
except: exit(RECEIVER_ERROR)

# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((IP, port))
log = list()

# Set initial sequence number and ack
seq, ack = 154, 0

# Opening handshake -> no connection or teardown packets will be dropped
# Received and sets the MSS for the TCP connection
(ack, _, _, MSS, _), addr = receive(server, MSS, log, True)
send(server, addr, [seq, ack, Packet.NONE, MSS, Action.SEND, Packet.SYNACK], log, True)
ack, seq = receive(server, MSS, log, True)[0][0:2]

# Open and write to file until teardown
with open(filename, "w") as file:
    while True:
        (ack, seq, data, MSS, p_type), addr = receive(server, MSS, log, False)
        # Handle teardown -> no connection or teardown packets will be dropped
        if p_type == Packet.FIN:
            send(server, addr, [seq, ack, Packet.NONE, MSS, Action.SEND, Packet.FINACK], log, True)
            ack, seq = receive(server, MSS, log, True)[0][0:2]
            break
        send(server, addr, [seq, ack, Packet.NONE, MSS, Action.SEND, Packet.ACK], log, True)
        file.write(data)

# Create log file
with open("Receiver_log.txt", "w") as logfile:
    tot_data, num_seg, num_dup = [0] * 3
    for a, b, c, d, e, f in log:
        if a == Action.RECEIVE: tot_data += f
        if a == Action.RECEIVE and c == Packet.DATA: num_seg += 1
        logfile.write(f"{a:<5} {b:<12} {c:<6} {d:<6} {f:<6} {e:<6}\n")
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Received (bytes):     {tot_data}\n")
    logfile.write(f"No. Data Segments Received:      {num_seg}\n")
    logfile.write(f"No. Duplicate Segments:          {num_dup}\n")
