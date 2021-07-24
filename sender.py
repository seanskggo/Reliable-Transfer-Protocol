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

##################################################################
# Functions
##################################################################

def create_ptp_segment(flag, seq, MSS, ack, data):
    length = len(data.encode())
    return struct.pack(f"!6sIII{length}s", 
        flag.encode(), seq, MSS, ack, data.encode()
    )

##################################################################
# PTP
##################################################################

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
# Opening handshake
client.sendto(create_ptp_segment("SYN", 0, MSS, 0, ""), (ip, port))
msg, addr = client.recvfrom(2048)
client.sendto(create_ptp_segment("ACK", 0, MSS, 0, ""), (ip, port))
# Open file for reading. If the file does not exist, throw error
with open(filename, "rb") as file:
    packet = file.read(MSS)
    while packet:
        client.sendto(packet, (ip, port))
        packet = file.read(MSS)

##################################################################
# Test Command
##################################################################

# Linux

# python3 sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1

# Powershell

# python sender.py localhost 8000 32KB.txt 256 16 600 0.1 seed1
