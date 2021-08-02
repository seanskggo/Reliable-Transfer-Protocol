##################################################################
# COMP3331/9331 Computer Networks and Applications 
# Assignment 2 | Term 2, 2021
# By Sean Go (z5310199)
#
# >>> Python Verion Used: 3.8.5
#
# NOTE: This is a helper file for sender.py and receiver.py
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

class TCP:
    def __init__(self, seq, ack) -> None:
        self.log = list()
        self.epoch = time.time()
        self.seq = seq
        self.ack = ack

    def get_time(self) -> float:
        return round((time.time() - self.epoch) * 1000, 3)

    def encode(self,seq, ack, data, packet_type) -> bytes:
        return json.dumps({ "seq": seq, "ack": ack, "data": data, "p_type": packet_type }).encode()

    def decode(self,packet) -> set:
        return json.loads(packet.decode()).values()

    def add_log(self,action, seq, ack, data, packet_type) -> None:
        self.log.append([action, self.get_time(), packet_type, seq, ack, len(data)])

    def get_log(self) -> list:
        return self.log

    def update_ack(self, seq, ack, data, packet_type) -> None:
        # Send and then increase the seq to get the expected return ack which matches this seq
        # Call this function after you send!
        if not self.ack: self.ack = seq
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
        else: self.ack += len(data)
        if not ack: return 
        self.seq = ack
        # if self.seq + len(data) == ack: self.seq = ack

class Sender(TCP):
    def __init__(self, client, seq, ack, window_length, addr) -> None:
        super().__init__(seq, ack)
        self.client = client
        self.addr = addr
        self.window = SenderWindow(window_length)

    def send(self, data, packet_type, add_to_window=False) -> None:
        self.client.sendto(self.encode(self.seq, self.ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, self.ack, data, packet_type)
        # add expected sequence number to window
        if add_to_window: self.window.add(self.seq + len(data), data)

    def receive(self, ack_window=False) -> None:
        msg, _ = self.client.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
        self.update_ack(seq, ack, data, packet_type)
        if ack_window: self.window.ack(ack)

    def drop(self, data, packet_type) -> None:
        self.add_log(Action.DROP, self.seq, self.ack, data, packet_type)

    def set_PL_module(self, seed, pdrop) -> None:
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        return True if random.random() > self.pdrop else False

class Receiver(TCP):
    def __init__(self, server, seq, ack) -> None:
        super().__init__(seq, ack)
        self.server = server
        self.addr = None
        self.window = ReceiverWindow(seq)

    def send(self, data, packet_type) -> None:
        self.server.sendto(self.encode(self.seq, self.ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, self.ack, data, packet_type)

    def receive(self) -> str:
        msg, self.addr = self.server.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
        self.update_ack(seq, ack, data, packet_type)
        self.window.send_cum_ack(self.ack, len(data))
        return data

##################################################################
# Sender Window Class
##################################################################

class SenderWindow:
    def __init__(self, window_length) -> None:
        self.size = window_length
        self.window = collections.deque([None] * window_length)

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
            
