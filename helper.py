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

import random
import time
import struct
import collections

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

class TCP:
    def __init__(self, seq, ack, MSS, MWS) -> None:
        self.log = list()
        self.epoch = time.time()
        self.seq = seq
        self.ack = ack
        self.HEADER_SIZE = 18
        self.MSS = MSS
        self.MWS = MWS
    
    def rm_null_bytes(self, byte_string) -> bytes:
        '''Remove null bytes from given bytes string'''
        return byte_string.strip(b'\x00')

    def decoder(self, payload) -> list:
        '''Decode all encoded children of payload'''
        return [self.rm_null_bytes(i).decode() if type(i) == bytes 
            else i for i in payload]

    def encoder(self, payload) -> list:
        '''Encode all dencoded children of payload'''
        return [i.encode() if type(i) == str else i for i in payload]

    def increment(self, packet_type, data) -> int:
        '''Return increment for sequence/ack number'''
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: 
            return 1
        else: return len(data)

    def get_time(self) -> float:
        '''Get time elapsed'''
        return round((time.time() - self.epoch) * 1000, 3)

    def get_log(self) -> list:
        '''Get current log'''
        return self.log

    def pack(self, data, action, packet_type, serial) -> bytes:
        '''Pack and log TCP segment. Returns serialised TCP segment'''
        pkt = struct.pack(serial, 
            *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, packet_type]))
        self.log.append([action, self.get_time(), packet_type, self.seq, self.ack, len(data)])
        self.seq += self.increment(packet_type, data)
        return pkt

    def unpack(self, msg, serial) -> set:
        '''Unpack and log TCP segment. Returns a set: (data, packet_type)'''
        seq, ack, data, MSS, MWS, packet_type = self.decoder(struct.unpack(serial, msg))
        self.log.append([Action.RECEIVE, self.get_time(), packet_type, seq, ack, len(data)])
        self.ack = seq + self.increment(packet_type, data)
        self.MSS = MSS
        self.MWS = MWS
        return (data, packet_type)

class Receiver(TCP):
    def __init__(self, server, seq, ack) -> None:
        super().__init__(seq, ack, None, None)
        self.server = server
        self.addr = None

    def send(self, data, packet_type) -> None:
        spec = (data, Action.SEND, packet_type, f"!II{self.MSS}sII2s")
        self.server.sendto(self.pack(*spec), self.addr)

    def receive_opening(self) -> None:
        msg, addr = self.server.recvfrom(self.HEADER_SIZE)
        self.unpack(msg, "!II0sII2s")
        self.addr = addr

    def receive(self) -> set:
        msg, _ = self.server.recvfrom(self.MSS + self.HEADER_SIZE)
        return self.unpack(msg, f"!II{self.MSS}sII2s")

class Sender(TCP):
    def __init__(self, client, addr, MSS, MWS, seq, ack) -> None:
        super().__init__(seq, ack, MSS, MWS)
        self.client = client
        self.addr = addr
        self.random = random.random()
        self.pdrop = None

    def send_opening(self, packet_type) -> None:
        spec = (Packet.NONE, Action.SEND, packet_type, "!II0sII2s")
        self.client.sendto(self.pack(*spec), self.addr)

    def send(self, data, packet_type) -> None:
        spec = (data, Action.SEND, packet_type, f"!II{self.MSS}sII2s")
        self.client.sendto(self.pack(*spec), self.addr)

    def receive(self) -> None:
        msg, _ = self.client.recvfrom(self.MSS + self.HEADER_SIZE)
        self.unpack(msg, f"!II{self.MSS}sII2s")

    def set_PL_module(self, seed, pdrop):
        '''Set seed and pdrop in sender instance'''
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        '''PL Module for dropping segments'''
        return True if self.random.random() > self.pdrop else False

# TCP Window class
class Window:
    def __init__(self, size) -> None:
        self.size = size
        self.window = collections.deque([])
    
    def send(self):
        pass
