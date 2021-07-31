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
        self.window = None
    
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
        self.window = None

    def send(self, data, packet_type) -> None:
        '''Send segment with data via socket'''
        spec = (data, Action.SEND, packet_type, f"!II{self.MSS}sII2s")
        self.server.sendto(self.pack(*spec), self.addr)

    def receive_opening(self) -> None:
        '''Receive initial segment without data and establish MSS and MWS'''
        msg, addr = self.server.recvfrom(self.HEADER_SIZE)
        self.unpack(msg, "!II0sII2s")
        self.addr = addr
        self.window = Window(self.MWS/self.MSS)

    def receive(self) -> set:
        '''Receive segment from socket'''
        msg, _ = self.server.recvfrom(self.MSS + self.HEADER_SIZE)
        return self.unpack(msg, f"!II{self.MSS}sII2s")

class Sender(TCP):
    def __init__(self, client, addr, MSS, MWS, seq, ack) -> None:
        super().__init__(seq, ack, MSS, MWS)
        self.client = client
        self.addr = addr
        self.pdrop = None

    def send_opening(self, packet_type) -> None:
        '''Send initial segment without data since MSS is unknown'''
        spec = (Packet.NONE, Action.SEND, packet_type, "!II0sII2s")
        self.client.sendto(self.pack(*spec), self.addr)
        self.window = Window(self.MWS/self.MSS)

    def send(self, data, packet_type, use_PL=True) -> None:
        '''Send segment with data via socket'''
        if self.PL_module() or not use_PL:
            spec = (data, Action.SEND, packet_type, f"!II{self.MSS}sII2s")
            self.client.sendto(self.pack(*spec), self.addr)
        else: self.pack(data, Action.DROP, packet_type, f"!II{self.MSS}sII2s")

    def receive(self) -> None:
        '''Receive segment from socket'''
        msg, _ = self.client.recvfrom(self.MSS + self.HEADER_SIZE)
        self.unpack(msg, f"!II{self.MSS}sII2s")

    def set_PL_module(self, seed, pdrop):
        '''Set seed and pdrop in sender instance'''
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        '''PL Module for dropping segments'''
        return True if random.random() > self.pdrop else False

# TCP Window class
class Window:
    def __init__(self, size) -> None:
        self.size = size
        self.window = collections.deque([])
    
    def add(self, ack, packet) -> None:
        if len(self.window) > self.size: raise Exception
        self.window.append((ack, packet))
    
    def ack(self, ack) -> None:
        for i in range(self.size):
            if self.window[i][0] == ack: self.window[i] = None
            else: print("Duplicate/ack not in window dropped")
        while self.window and self.window[0]: self.window.popleft()

    def printWindow(self) -> None:
        print(self.window)