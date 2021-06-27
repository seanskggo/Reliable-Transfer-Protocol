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

error = 'USAGE: python receiver.py receiver_port FileReceiverd.txt'

if (len(sys.argv) != 3): exit(error)
try:
    port, filename = int(sys.argv[1]), sys.argv[2]
except:
    exit(error)


