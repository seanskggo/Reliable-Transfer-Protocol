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
# Types
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

##################################################################
# TCP Class
##################################################################

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

##################################################################
# Receiver Class
##################################################################

class Receiver(TCP):
    def __init__(self, server, seq, ack) -> None:
        super().__init__(seq, ack, None, None)
        self.server = server
        self.addr = None
        self.window = None

    def send_ack(self, data, packet_type) -> set:
        '''Send segment with data via socket'''
        pkt = struct.pack(f"!II{self.MSS}sII2s", 
            *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, packet_type]))
        self.log.append([Action.SEND, self.get_time(), packet_type, self.seq, self.ack, len(data)])
        self.seq += self.increment(packet_type, data)
        self.server.sendto(pkt, self.addr)
        return (self.ack, data)

    def receive_opening(self) -> None:
        '''Receive initial segment without data and establish MSS and MWS'''
        msg, addr = self.server.recvfrom(self.HEADER_SIZE)
        seq, ack, data, MSS, MWS, packet_type = self.decoder(struct.unpack("!II0sII2s", msg))
        self.log.append([Action.RECEIVE, self.get_time(), packet_type, seq, ack, len(data)])
        self.addr = addr
        self.MSS = MSS
        self.MWS = MWS
        self.ack = seq + self.increment(packet_type, data)
        self.window = ReceiverWindow(self.ack)

    def receive(self) -> set:
        '''Receive segment from socket'''
        msg, _ = self.server.recvfrom(self.MSS + self.HEADER_SIZE)
        seq, ack, data, _, _, packet_type = self.decoder(struct.unpack(f"!II{self.MSS}sII2s", msg))
        self.log.append([Action.RECEIVE, self.get_time(), packet_type, seq, ack, len(data)])
        self.ack = seq + self.increment(packet_type, data)
        self.ack = self.window.send_cum_ack(seq, len(data))
        return (data, packet_type)

##################################################################
# Sender Class
##################################################################

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
        self.window = SenderWindow(int(self.MWS/self.MSS))

    def pack(self, data, action, packet_type, serial) -> bytes:
        '''Pack and log TCP segment. Returns serialised TCP segment'''
        pkt = struct.pack(serial, 
            *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, packet_type]))
        self.log.append([action, self.get_time(), packet_type, self.seq, self.ack, len(data)])
        self.seq += self.increment(packet_type, data)
        return pkt

    ## Use window in front
    def send(self, data, packet_type, use_PL=True, handshake=False) -> set:
        '''Send segment with data via socket'''
        if self.PL_module() or not use_PL: 
            pkt = struct.pack(f"!II{self.MSS}sII2s", 
                *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, packet_type]))
            self.log.append([Action.SEND, self.get_time(), packet_type, self.seq, self.ack, len(data)])
            self.client.sendto(pkt, self.addr)
        else: self.log.append([Action.DROP, self.get_time(), packet_type, self.seq, self.ack, len(data)])
        if not handshake: self.window.add(self.seq, data)
        self.seq += self.increment(packet_type, data)
        return (self.seq, data)

    def receive(self, handshake=False) -> int:
        '''Receive segment from socket'''
        msg, _ = self.client.recvfrom(self.MSS + self.HEADER_SIZE)
        ack = self.unpack(msg, f"!II{self.MSS}sII2s")
        if not handshake: self.window.ack(ack)
        self.window.printWindow(True)
        return self.ack

    def unpack(self, msg, serial) -> int:
        '''Unpack and log TCP segment. Returns a set: (data, packet_type, seq_of_received)'''
        seq, ack, data, MSS, MWS, packet_type = self.decoder(struct.unpack(serial, msg))
        self.log.append([Action.RECEIVE, self.get_time(), packet_type, seq, ack, len(data)])
        self.ack = seq + self.increment(packet_type, data)
        return ack

    def set_PL_module(self, seed, pdrop):
        '''Set seed and pdrop in sender instance'''
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        '''PL Module for dropping segments'''
        return True if random.random() > self.pdrop else False

##################################################################
# Sender Window Class
##################################################################

class SenderWindow:
    def __init__(self, size) -> None:
        self.size = size
        self.window = collections.deque([None] * size)

    def add(self, ack, packet) -> None:
        if all(self.window): raise Exception
        for i in range(self.size - 1, -1, -1):
            if self.window[i]: 
                self.window[i + 1] = (ack, packet)
                return
        self.window[0] = (ack, packet)

    def ack(self, ack) -> None:
        for i in range(len(self.window)):
            if self.window and self.window[i] and self.window[i][0] == ack: 
                self.window[i] = None
                while self.window and not self.window[0]: self.window.popleft()
                self.window += [None] * (self.size - len(self.window))
                return
        print("Ack not in window dropped: " + str(ack))

    def data_to_resend(self) -> list:
        return [i for i in self.window if i]

    def printWindow(self, ack_only=False) -> None:
        if ack_only: print([i[0] if i else None for i in self.window])
        else: print(self.window)

##################################################################
# Receiver Window Class
##################################################################

class ReceiverWindow:
    def __init__(self, seq) -> None:
        self.seq = seq

    def send_cum_ack(self, ack, length) -> int:
        if self.seq == ack: 
            self.seq += length
            return ack
        else: return self.seq
            
