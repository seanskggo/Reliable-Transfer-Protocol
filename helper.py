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
import collections
import json

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
# Functions
##################################################################

log = list()
epoch = time.time()

def get_time() -> float:
    return round((time.time() - epoch) * 1000, 3)

def encode(seq, ack, data, packet_type) -> bytes:
    return json.dumps({ "seq": seq, "ack": ack, "data": data, "p_type": packet_type }).encode()

def decode(packet) -> set:
    return json.loads(packet.decode()).values()

def add_log(action, seq, ack, data, packet_type) -> None:
    log.append([action, get_time(), packet_type, seq, ack, len(data)])

def get_log() -> list:
    return log

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
            
