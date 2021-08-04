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
# COMMENT SECTION - GET RID OF LATER
#
# Problem 1: When a window acks and frees a space, no new segment
#            is sent immediately e.g. [1018, 1082, 1122, None] 
#            should be [1018, 1082, 1122, "new segment number"]
# Problem 2: When there are two timeouts per window, the timeout
#            is twice as long: e.g. two timeouts of 600ms:
#            rcv   3.531        A      155    0      634   
#            snd   1205.078     D      634    64     155  
# Problem 3: Currently, the UDP buffer size is 2048 -> make it 
#            dynamic
# Problem 4: Need to calculate dropped packets etc well
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

# Packet action types
class Action:
    SEND = "snd"
    RECEIVE = "rcv"
    DROP = "drop"

class Data:
    NONE = ""
    BUFFERED = "bfd"

##################################################################
# Functions
##################################################################

class TCP:
    def __init__(self, seq, ack) -> None:
        '''Initialise TCP instance'''
        self.log = list()
        self.epoch = time.time()
        self.seq = seq
        self.ack = ack

    def get_time(self) -> float:
        '''Get the time since start of program'''
        return round((time.time() - self.epoch) * 1000, 3)

    def encode(self,seq, ack, data, packet_type) -> bytes:
        '''Jsonify and encode packet'''
        return json.dumps({ "seq": seq, "ack": ack, "data": data, "p_type": packet_type }).encode()

    def decode(self,packet) -> set:
        '''Decode and extract data from jsonified packet'''
        return json.loads(packet.decode()).values()

    def add_log(self,action, seq, ack, data, packet_type) -> None:
        '''Log packet information'''
        self.log.append([action, self.get_time(), packet_type, seq, ack, len(data)])

    def get_log(self) -> list:
        '''Return log'''
        return self.log

class Sender(TCP):

    def __init__(self, client, seq, ack, window_length, addr) -> None:
        '''Initialise Sender instance'''
        super().__init__(seq, ack)
        self.client = client
        self.addr = addr
        self.window = SenderWindow(window_length)

    def send(self, data, packet_type, handshake=False) -> None:
        '''Encode data and add to current window. Logs and sends the packet'''
        self.client.sendto(self.encode(self.seq, self.ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, self.ack, data, packet_type)
        self.__update_seq(data, packet_type)
        if not handshake: self.window.add(self.seq, self.ack, data)

    def resend(self, seq, ack, data, packet_type) -> None:
        '''Log and send the data as a packet without adding to window'''
        self.client.sendto(self.encode(seq, ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, seq, ack, data, packet_type)

    def receive(self, handshake=False) -> None:
        '''Log data with current sequence and ack number. Drops the packet'''
        msg, _ = self.client.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        self.add_log(Action.RECEIVE, seq, ack, data, packet_type)
        self.__update_ack(seq, data, packet_type)
        if not handshake: self.window.ack(ack)

    def drop(self, data, packet_type) -> None:
        '''Log data with current sequence and ack number. Drops the packet'''
        self.add_log(Action.DROP, self.seq, self.ack, data, packet_type)
        self.__update_seq(data, packet_type)
        self.window.add(self.seq, self.ack, data)

    def set_PL_module(self, seed, pdrop) -> None:
        '''Set drop rate and seed for PL module'''
        random.seed(seed)
        self.pdrop = pdrop

    def PL_module(self) -> bool:
        '''Activate the PL module'''
        return True if random.random() > self.pdrop else False

    def __update_ack(self, seq, data, packet_type) -> None:
        '''Given a receiver's sequence number, update the sender's ack number '''
        if not self.ack: self.ack = seq
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
        else: self.ack += len(data)

    def __update_seq(self, data, packet_type) -> None:
        '''Update sequence number to the next expected sequence number'''
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)

class Receiver(TCP):

    def __init__(self, server, seq, ack) -> None:
        '''Initialise Receiver instance'''
        super().__init__(seq, ack)
        self.server = server
        self.addr = None
        self.window = None

    def send(self, data, packet_type, handshake=False) -> None:
        '''Encode data with current cumulative ack. Logs and sends the packet'''
        cum_ack = self.ack if handshake else self.window.get_cum_ack()
        self.server.sendto(self.encode(self.seq, cum_ack, data, packet_type), self.addr)
        self.add_log(Action.SEND, self.seq, cum_ack, data, packet_type)
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.seq += 1
        else: self.seq += len(data)

    def receive(self, handshake=False) -> str:
        msg, self.addr = self.server.recvfrom(2048)
        seq, ack, data, packet_type = self.decode(msg)
        self.add_log(Action.RECEIVE, seq, ack, data, packet_type)




        if handshake:
            if not self.ack: self.ack = seq
            if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
        else:
            if not self.window: self.window = ReceiverWindow(seq)
            buffered_data = self.window.get_buffered_data(seq)
            if self.ack != seq:
                print("out of order packet will be buffered")
                self.window.add_to_buffer(seq, data)
                if not packet_type == Packet.FIN:
                    if self.window.update_cum_ack(seq, len(data)): self.ack += len(data)
                if not self.ack: self.ack = seq
                if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
                return Data.BUFFERED
            elif buffered_data: 
                print("duplicate packet dropped at receiver " + str(seq))
                if not packet_type == Packet.FIN:
                    if self.window.update_cum_ack(seq, len(data)): self.ack += len(data)
                if not self.ack: self.ack = seq
                if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: self.ack += 1
                return buffered_data
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
        '''Initialise Sender Window instance'''
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
        '''Initialise Receiver Window instance'''
        self.seq = seq
        self.buffer = set()

    def update_cum_ack(self, ack, length) -> bool:
        '''Update current cumulative ack'''
        outcome = self.seq == ack
        self.seq = self.seq + length if outcome else self.seq
        return outcome

    def get_cum_ack(self) -> int:
        '''Get current cumulative ack'''
        return self.seq

    def add_to_buffer(self, seq, data) -> None:
        '''Add sequence number and data to buffer'''
        self.buffer.add((seq, data))

    def get_buffered_data(self, seq) -> str:
        '''Given a sequence number as key, return the buffered data'''
        rtr = [(i, j) for i, j in self.buffer if i == seq]
        if len(rtr) > 1: raise Exception        # REMOVE THIS LATER
        return self.__remove_data(rtr)

    def __remove_data(self, rtr) -> str:
        '''Remove data from buffer and return the deleted data'''
        if not rtr: return None
        self.buffer.remove(rtr[0])
        return rtr[0][1]
