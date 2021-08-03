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

class Sender(TCP):

    # DESCRIPTION
    # Sends packet then increases the seq number independently then adds to window
    # Received packets are acked and removed -> else resend

    def __init__(self, client, seq, ack, window_length, addr) -> None:
        super().__init__(seq, ack)
        self.client = client
        self.addr = addr
        self.window = SenderWindow(window_length)

    def send(self, data, packet_type, handshake=False) -> None:
        self.client.sendto(self.encode(self.seq, self.ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, self.ack, data, packet_type)
        # add expected sequence number to window
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)
        if not handshake: self.window.add(self.seq, self.ack, data)

    def resend(self, seq, ack, data, packet_type) -> None:
        self.client.sendto(self.encode(seq, ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, seq, ack, data, packet_type)

    def receive(self, handshake=False) -> None:
        msg, _ = self.client.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
        self.update_ack(seq, ack, data, packet_type)
        if not handshake: self.window.ack(ack)

    def drop(self, data, packet_type) -> None:
        self.add_log(Action.DROP, self.seq, self.ack, data, packet_type)
        # add expected sequence number to window
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)
        self.window.add(self.seq, self.ack, data)

    def set_PL_module(self, seed, pdrop) -> None:
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        return True if random.random() > self.pdrop else False

    def update_ack(self, seq, ack, data, packet_type) -> None:
        # If current ack is 0 i.e. opening handshake, then make incoming
        # sequence number the new ack number
        if not self.ack: self.ack = seq
        # Update the ack number
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
        else: self.ack += len(data)
        # # If in coming ack from reciever is not 0 i.e. from initial opening handshake, make the 
        # # ack the new sequence number. Otherwise, the packet is a duplicate ack -> do not modify seq
        # if ack: self.seq = ack

class Receiver(TCP):

    # DESCRIPTION
    # Receives packets and checks if they are in order using sequence numbers. Otherwise, 
    # store in buffer and then transmit cumulative ack

    def __init__(self, server, seq, ack) -> None:
        super().__init__(seq, ack)
        self.server = server
        self.addr = None
        self.window = None

    def send(self, data, packet_type, handshake=False) -> None:
        # Send cumulative ack
        seq_to_send = self.ack if handshake else self.window.get_cum_ack()
        self.server.sendto(self.encode(self.seq, seq_to_send, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, seq_to_send, data, packet_type)
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)

    def receive(self, handshake=False) -> str:
        # Receive and log packet data
        msg, self.addr = self.server.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        if handshake:
            self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
            if not self.ack: self.ack = seq
            if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
        else:
            if not self.window: self.window = ReceiverWindow(seq)
            if self.ack != seq:
                print("out of order packet will be buffered")
                self.window.add_to_buffer(seq, data)
                if not packet_type == Packet.FIN:
                    if self.window.update_cum_ack(seq, len(data)): self.ack += len(data)
                if not self.ack: self.ack = seq
                if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
                return "|BUFFERED|"
            elif self.window.check_buffer(seq): 
                print("duplicate packet dropped at receiver " + str(seq))
                if not packet_type == Packet.FIN:
                    if self.window.update_cum_ack(seq, len(data)): self.ack += len(data)
                if not self.ack: self.ack = seq
                if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
                return self.window.get_buffered_data(seq)
            self.window.add_to_buffer(seq, data)
            self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
            # update window accordingly
            if not packet_type == Packet.FIN:
                if self.window.update_cum_ack(seq, len(data)): self.ack += len(data)
            if not self.ack: self.ack = seq
            if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
            print("packet received at receiver " + str(seq))
        # print(self.seq, data)
        return data

##################################################################
# Sender Window Class
##################################################################

class SenderWindow:
    def __init__(self, window_length) -> None:
        self.size = window_length
        self.window = collections.deque([None] * window_length)

    def add(self, seq, ack, packet) -> None:
        if all(self.window): raise Exception
        for i in range(self.size - 1, -1, -1):
            if self.window[i]: 
                self.window[i + 1] = (seq, ack, packet)
                return
        self.window[0] = (seq, ack, packet)

    def ack(self, ack) -> None:
        for i in range(len(self.window)):
            if self.window and self.window[i] and self.window[i][0] == ack: 
                self.window[i] = None
                while self.window and not self.window[0]: self.window.popleft()
                self.window += [None] * (self.size - len(self.window))
                print("Sender: Ack received: " + str(ack))
                self.printWindow(True)
                return
        print("Sender: Ack not in window dropped: " + str(ack))
        self.printWindow(True)

    def data_to_resend(self) -> list:
        def modify(pkt):
            a, b, c = pkt
            return (a - len(c), b, c)
        return [modify(i) for i in self.window if i]

    def printWindow(self, ack_only=False) -> None:
        if ack_only: print([i[0] if i else None for i in self.window])
        else: print(self.window)

##################################################################
# Receiver Window Class
##################################################################

class ReceiverWindow:
    def __init__(self, seq) -> None:
        self.seq = seq
        self.buffer = set()

    def update_cum_ack(self, ack, length) -> bool:
        outcome = self.seq == ack
        self.seq = self.seq + length if outcome else self.seq
        return outcome

    def get_cum_ack(self):
        return self.seq

    def add_to_buffer(self, seq, data):
        self.buffer.add((seq, data))

    def check_buffer(self, seq):
        return seq in [i for i, _ in self.buffer]

    def get_buffered_data(self, seq):
        for i, j in self.buffer:
            if i == seq: return j
        return None
            
