from collections import namedtuple

PeerData = namedtuple("PeerData", "ip port protocol")
PacketInfo = namedtuple("PacketInfo", "packet direction")

def init():
    global CLIENT_TO_SERVER
    global SERVER_TO_CLIENT
    global REQUEST
    global RESPONSE
    CLIENT_TO_SERVER = 1
    SERVER_TO_CLIENT = 2
    REQUEST = 1
    RESPONSE = 2

