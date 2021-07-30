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

    # Return increment for sequence/ack number
    def increment(self, packet_type, data) -> int:
        if packet_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: 
            return 1
        else: len(data)

    # Get time elapsed
    def get_time(self) -> float:
        return round((time.time() - self.epoch) * 1000, 3)

    # Get current log
    def get_log(self) -> list:
        return self.log

    # Pack and log TCP segment. Returns serialised TCP segment
    def pack(self, data, action, packet_type, serial) -> bytes:
        pkt = struct.pack(serial, 
            *self.encoder([self.seq, self.ack, data, self.MSS, self.MWS, packet_type]))
        self.log.append([action, self.get_time(), packet_type, self.seq, self.ack, len(data)])
        self.seq += self.increment(packet_type, data)
        return pkt

    # Unpack and log TCP segment. Returns a set: (data, packet_type)
    def unpack(self, msg, serial) -> set:
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

    def send_opening(self, packet_type) -> None:
        spec = (Packet.NONE, Action.SEND, packet_type, "!II0sII2s")
        self.client.sendto(spec, self.addr)

    def send(self, data, packet_type) -> None:
        spec = (data, Action.SEND, packet_type, f"!II{self.MSS}sII2s")
        self.client.sendto(spec, self.addr)

    def receive(self) -> None:
        msg, _ = self.client.recvfrom(self.MSS + self.HEADER_SIZE)
        self.unpack(msg, f"!II{self.MSS}sII2s")

# TCP Window class
class Window:
    def __init__(self, size) -> None:
        self.size = size
        self.window = collections.deque([])
    
    def send(self):
        pass

##################################################################
# Past Ideas
##################################################################

# Recieve and log TCP packet
def receive(body, MSS, log, empty) -> set:
    mod = TCP()
    msg, addr = body.recvfrom(MSS + 18)
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
    mod = TCP()
    seq, ack, data, MSS, MWS, s_type, p_type = payload
    serial = "!II0sII2s" if empty else f"!II{MSS}sII2s"
    pkt = struct.pack(serial, *mod.encoder([seq, ack, data, MSS, MWS, p_type]))
    ttime = round((time.time() - EPOCH) * 1000, 3)
    log.append([s_type, ttime, p_type, seq, ack, len(data)])
    if p_type in [Packet.FIN, Packet.FINACK, Packet.SYN, Packet.SYNACK]: seq += 1
    else: seq += len(data)
    if s_type != Action.DROP: body.sendto(pkt, addr)
    return seq