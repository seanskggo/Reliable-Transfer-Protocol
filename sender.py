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

##################################################################
# Constants
##################################################################

error = 'USAGE: python sender.py receiver_host_ip receiver_port \
    FileToSend.txt MWS MSS timeout pdrop seed'

if (len(sys.argv) != 9): exit(error)
try:
    ip, port, filename = int(sys.argv[1]), sys.argv[2]
except:
    exit(error)