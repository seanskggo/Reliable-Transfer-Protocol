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
# PTP
##################################################################

# Parse commandline arguments
if (len(sys.argv) != 3): exit(error)
try: port, filename = int(sys.argv[1]), sys.argv[2]
except: exit(error)
# Create UDP socket server
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind((ip, port))
# Open and write to file until teardown
with open(filename, "wb") as file:
    while True:
        msg, addr = server.recvfrom(2048) # Change buffer size -> SYN then get buffer size from header
        file.write(msg)

# python3 receiver.py 8000 temp.txt 