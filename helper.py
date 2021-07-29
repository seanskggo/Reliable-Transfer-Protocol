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

import time
import struct

##################################################################
# Constants
##################################################################

IP = '127.0.0.1'
RECEIVER_ERROR = \
    'USAGE: python receiver.py receiver_port FileReceiverd.txt'
SENDER_ERROR = \
    'USAGE: python sender.py receiver_host_ip receiver_port ' \
    + 'FileToSend.txt MWS MSS timeout pdrop seed'
PDROP_ERROR = 'Pdrop parameter must be between 0 and 1'
MSS_ERROR = 'Maximum Segment Size must be greater than 0'
EPOCH = time.time()
HEADER_SIZE = 14

##################################################################
# API
##################################################################

# Packet types
class Packet:
    SYN = "S"
    ACK = "A"
    DATA = "D"
    SYNACK = "SA"
    FIN = "F"
    FINACK = "FA"
    NONE = ""

# Packet action types
class Action:
    SEND = "snd"
    RECEIVE = "rcv"
    DROP = "drop"

# Remove null bytes from given bytes string
def rm_null_bytes(byte_string) -> bytes:
    return byte_string.strip(b'\x00')

# Decode all encoded children of payload
def decoder(payload) -> list:
    return [rm_null_bytes(i).decode() if type(i) == bytes 
        else i for i in payload]

# Encode all dencoded children of payload
def encoder(payload) -> list:
    return [i.encode() if type(i) == str else i for i in payload]

# Recieve and log TCP packet
def receive(body, MSS, log, empty) -> set:
    msg, addr = body.recvfrom(MSS + HEADER_SIZE)
    ttime = round((time.time() - EPOCH) * 1000, 3)
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    seq, ack, data, MSS, p_type = decoder(struct.unpack(serial, msg))
    log.append([Action.RECEIVE, ttime, p_type, seq, ack, len(data)])
    if p_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: seq += 1
    else: seq += len(data)
    return ((seq, ack, data, MSS, p_type), addr)

# Send and log TCP packet
# payload: [seq, ack, data, MSS, send_type, packet_type]
def send(body, addr, payload, log, empty) -> set:
    seq, ack, data, MSS, s_type, p_type = payload
    serial = "!II0sI2s" if empty else f"!II{MSS}sI2s"
    pkt = struct.pack(serial, *encoder([seq, ack, data, MSS, p_type]))
    ttime = round((time.time() - EPOCH) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    if s_type != Action.DROP: body.sendto(pkt, addr)
