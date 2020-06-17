import scapy.all as scapy
import scapy.layers.inet as scapy_layers
import re
from collections import namedtuple

PeerData = namedtuple("PeerData", "ip port")

def parsePcap(pcap):
    return scapy.rdpcap(pcap)

def isCallIdInPacket(packet, callid):
    sipMsg = packet.load.lower().decode('utf-8')
    return True if re.search(r'\r\ncall-id:.*{}\r\n'.format(callid), sipMsg) else False

def filterPacketsByCallid(packets, callid):
    filteredPackets = []
    for packet in packets:
        if isCallIdInPacket(packet, callid):
            filteredPackets.append(packet)
            scapy.ls(packet)
    return filteredPackets, len(filteredPackets)

def getClientServerIpFromFirstPacket(packet):
    return packet[scapy_layers.IP].src, packet[scapy_layers.IP].dst

def getClientServerPortFromFirstPacket(packet):
    if packet.haslayer(scapy_layers.UDP):
        return packet[scapy_layers.UDP].sport, packet[scapy_layers.UDP].dport
    elif packet.haslayer(scapy_layers.TCP):
        return packet[scapy_layers.TCP].sport, packet[scapy_layers.TCP].dport
    else:
        print("PROTOCOL NOT SUPPORTED, ONLY SUPPORTED: UDP/TCP")
        exit(0)

def assertValidPackets(callid, howManyPackets):
    if howManyPackets == 0:
        print("Call-Id: {} not in pcap".format(callid))
        exit(0)


def getClientServerDataFrom(firstPacket):
    clientIp, serverIp = getClientServerIpFromFirstPacket(firstPacket[0])
    clientPort, serverPort = getClientServerPortFromFirstPacket(firstPacket[0])
    client = PeerData(ip=clientIp, port=clientPort)
    server = PeerData(ip=serverIp, port=serverPort)
    return client, server

def pcapHandler(packets, callid):
    filteredPackets, howManyPackets = filterPacketsByCallid(packets, callid)
    assertValidPackets(callid, howManyPackets)
    client, server = getClientServerDataFrom(filteredPackets[0])
