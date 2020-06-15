import scapy.all as scapy
import scapy.layers.inet as scapy_layers
import re

def parsePcap(pcap):
    return scapy.rdpcap(pcap)

def isCallIdInPacket(packet, callid):
    sipMsg = packet.load.lower()
    return True if re.search(r'\r\ncall-id:.*{}\r\n'.format(callid), sipMsg) else False

def filterPacketsByCallid(packets, callid):
    filteredPackets = []
    for packet in packets:
        if isCallIdInPacket(packet, callid):
            filteredPackets.append(packet)
    return filteredPackets, len(filteredPackets)

def pcapHandler(packets, callid):
    filteredPackets, howManyPackets = filterPacketsByCallid(packets, callid)
#         sport = packet[scapy_layers.UDP].sport
#         dport = packet[scapy_layers.UDP].dport
#         if (sport == 5060 or dport == 5060):
    print(len(filteredPackets))
    for packet in filteredPackets:
        print(packet.load)
