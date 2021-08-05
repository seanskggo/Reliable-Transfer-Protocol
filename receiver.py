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

IP = '127.0.0.1'
RECEIVER_ERROR = \
    'USAGE: python receiver.py receiver_port FileReceiverd.txt'

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(RECEIVER_ERROR)
try: port, filename = int(sys.argv[1]), sys.argv[2]
except: exit(RECEIVER_ERROR)

# Set initial sequence and acknowledgement number
seq, ack = 154, 0

# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((IP, port))

# Instantiate receiver class
receiver = Receiver(server, seq, ack)

# Opening handshake
receiver.receive(handshake=True)
receiver.send(Data.NONE, Packet.SYNACK, handshake=True)
receiver.receive(handshake=True)

# Open and write to file until teardown
with open(filename, "w") as file:
    data = receiver.receive()
    while data:
        receiver.send(Data.NONE, Packet.ACK)
        if data != Data.BUFFERED: file.write(data)
        data = receiver.receive()
    receiver.send(Data.NONE, Packet.FINACK, handshake=True)
    receiver.receive(handshake=True)

# Create log file
with open("Receiver_log.txt", "w") as logfile:
    for a, b, c, d, e, f in receiver.get_log():
        logfile.write(f"{a:<5} {b:<12} {c:<4} {d:<8} {f:<6} {e:<6}\n")
    tot_data, num_seg, num_dup = receiver.get_stats()
    logfile.write("\n--------- Log File Statistics ---------\n\n")
    logfile.write(f"Total Data Received (bytes):     {tot_data}\n")
    logfile.write(f"No. Data Segments Received:      {num_seg}\n")
    logfile.write(f"No. Duplicate Segments:          {num_dup}\n\n")
