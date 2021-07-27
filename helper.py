##################################################################
# COMP3331/9331 Computer Networks and Applications 
# Assignment 2 | Term 2, 2021
# By Sean Go (z5310199)
#
# >>> Python Verion Used: 3.8.5
#
# NOTE: This file is a helper file for sender.py and receiver.py
##################################################################

##################################################################
# Imports
##################################################################

# Remove null bytes from given bytes string
def rm_null_bytes(byte_string):
    return byte_string.strip(b'\x00')

# Decode all encoded children of payload
def decoder(payload):
    return [rm_null_bytes(i).decode() if type(i) == bytes else i for i in payload]

# Encode all dencoded children of payload
def encoder(payload):
    return [i.encode() if type(i) == str else i for i in payload]
