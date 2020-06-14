import scapy.all as scapy
import scapy.layers.inet as scapy_layers

def parsePcap(pcap):
    return scapy.rdpcap(pcap)
#     for packet in packets:
#         sport = packet[scapy_layers.UDP].sport
#         dport = packet[scapy_layers.UDP].dport
#         if (sport == 5060 or dport == 5060):
#             print(packet.load)
