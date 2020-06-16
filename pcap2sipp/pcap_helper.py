import scapy.all as scapy
import scapy.layers.inet as scapy_layers
import re

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
    return filteredPackets, len(filteredPackets)

#         sport = packet[scapy_layers.UDP].sport
#         dport = packet[scapy_layers.UDP].dport
#         if (sport == 5060 or dport == 5060):


def getClientServerIpFromFirstPacket(packet):
    return packet[scapy_layers.IP].src, packet[scapy_layers.IP].dst

def assertValidPackets(callid, howManyPackets):
    if howManyPackets == 0:
        print("Call-Id: {} not in pcap".format(callid))
        exit(0)

def pcapHandler(packets, callid):
    filteredPackets, howManyPackets = filterPacketsByCallid(packets, callid)
    assertValidPackets(callid, howManyPackets)
    clientIp, serverIp = getClientServerIpFromFirstPacket(filteredPackets[0])
    print(len(filteredPackets))
    for packet in filteredPackets:
        scapy.ls(packet)
