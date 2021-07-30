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
import collections

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
HEADER_SIZE = 18

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

class Modifier:
    # Remove null bytes from given bytes string
    def rm_null_bytes(self, byte_string) -> bytes:
        return byte_string.strip(b'\x00')

    # Decode all encoded children of payload
    def decoder(self, payload) -> list:
        return [self.rm_null_bytes(i).decode() if type(i) == bytes 
            else i for i in payload]

    # Encode all dencoded children of payload
    def encoder(self, payload) -> list:
        return [i.encode() if type(i) == str else i for i in payload]

# Recieve and log TCP packet
def receive(body, MSS, log, empty) -> set:
    mod = Modifier()
    msg, addr = body.recvfrom(MSS + HEADER_SIZE)
    ttime = round((time.time() - EPOCH) * 1000, 3)
    serial = "!II0sII2s" if empty else f"!II{MSS}sII2s"
    seq, ack, data, MSS, MWS, p_type = mod.decoder(struct.unpack(serial, msg))
    log.append([Action.RECEIVE, ttime, p_type, seq, ack, len(data)])
    if p_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: seq += 1
    else: seq += len(data)
    return ((seq, ack, data, MSS, MWS, p_type), addr)

# Send and log TCP packet
# payload: [seq, ack, data, MSS, send_type, packet_type]
def send(body, addr, payload, log, empty) -> int:
    mod = Modifier()
    seq, ack, data, MSS, MWS, s_type, p_type = payload
    serial = "!II0sII2s" if empty else f"!II{MSS}sII2s"
    pkt = struct.pack(serial, *mod.encoder([seq, ack, data, MSS, MWS, p_type]))
    ttime = round((time.time() - EPOCH) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    if p_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: seq += 1
    else: seq += len(data)
    if s_type != Action.DROP: body.sendto(pkt, addr)
    return seq

class Sender(Modifier):
    def __init__(self, client, addr, MSS, MWS, seq, ack) -> None:
        self.client = client
        self.addr = addr
        self.MSS = MSS
        self.MWS = MWS
        self.log = list()
        self.epoch = time.time()
        self.seq = seq
        self.ack = ack

    def send_empty(self, packet_type) -> None:
        pkt = struct.pack("!II0sII2s", 
            *self.encoder([self.seq, self.ack, Packet.NONE, self.MSS, self.MWS, packet_type]))
        ttime = round((time.time() - self.epoch) * 1000, 3)
        self.log.append([Action.SEND, ttime, packet_type, self.seq, self.ack, len(Packet.NONE)])
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        self.client.sendto(pkt, self.addr)

    def send_data(self, data):
        pkt = struct.pack(f"!II{self.window_info[0]}sII2s", 
            *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, Packet.DATA]))
        ttime = round((time.time() - self.epoch) * 1000, 3)
        self.log.append([Action.SEND, ttime, Packet.DATA, self.seq, self.ack, len(data)])
        self.client.sendto(pkt, self.addr)
        self.seq += len(data)

    def receive_empty(self) -> None:
        msg, _ = self.client.recvfrom(self.MSS + HEADER_SIZE)
        ttime = round((time.time() - self.epoch) * 1000, 3)
        self.ack, seq, data, _, _, packet_type = self.decoder(struct.unpack("!II0sII2s", msg))
        self.log.append([Action.RECEIVE, ttime, packet_type, self.seq, self.ack, len(data)])
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)

    def get_log(self) -> list:
        return self.log

# TCP Window class
class Window:
    def __init__(self, size) -> None:
        self.size = size
        self.window = collections.deque([])
    
    def send(self):
        pass