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

##################################################################
# Constants
##################################################################

error = 'USAGE: python receiver.py receiver_port FileReceiverd.txt'
ip = '127.0.0.1'

##################################################################
# Functions
##################################################################

def create_ptp_segment(flag, length, seq, ack, data):
    return (
        f"Flags: {flag}\r\n"                    # SYN/SYNACK/ACK/DATA/FIN
        + f"MSS: {length}\r\n"                  # Maximum segment size
        + f"Sequence number: {seq}\r\n"         # Sequence number
        + f"Acknowledgement number: {ack}\r\n"  # Acknowledgement number
        + f"\r\n"   
        + f"TCP payload: {data}\r\n"            # Payload
    ).encode()

##################################################################
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(error)
try: port, filename, MSS = int(sys.argv[1]), sys.argv[2], None
except: exit(error)
# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((ip, port))
# Opening handshake
msg, addr = server.recvfrom(2048)
server.sendto(create_ptp_segment("SYNACK", MSS, 0, 0, ""), addr)
msg, addr = server.recvfrom(2048)
print(msg.decode())

# # Open and write to file until teardown
# with open(filename, "wb") as file:
#     while True:
#         msg, addr = server.recvfrom(2048) # Change buffer size -> SYN then get buffer size from header
#         file.write(msg)

# # python3 receiver.py 8000 temp.txt 