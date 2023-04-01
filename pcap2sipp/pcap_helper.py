import scapy.all as scapy
import scapy.layers.inet as scapy_layers
import re
import settings

def parsePcap(pcap):
    return scapy.rdpcap(pcap)

def isCallIdInPacket(packet, callid):
    sipMsg = packet.load.lower().decode('utf-8')
    callid = re.escape(callid.lower())
    return True if re.search(r'\r\ncall-id:.*{}\r\n'.format(callid), sipMsg) else False

def filterPacketsByCallid(packets, callid):
    filteredPackets = []
    for packet in packets:
        if isCallIdInPacket(packet, callid):
            filteredPackets.append(packet)
            scapy.ls(packet)
    return filteredPackets, len(filteredPackets)

def getClientServerIpFrom(packet):
    return packet[scapy_layers.IP].src, packet[scapy_layers.IP].dst

def getClientServerPortFrom(packet, protocol):
    return packet[protocol].sport, packet[protocol].dport
        
def getClientServerProtocolFrom(packet):
    if packet.haslayer(scapy_layers.UDP):
        return scapy_layers.UDP
    elif packet.haslayer(scapy_layers.TCP):
        return scapy_layers.TCP
    else:
        print("PROTOCOL NOT SUPPORTED, ONLY SUPPORTED: UDP/TCP")
        exit(0)

def getClientServerDataFrom(firstPacket):
    clientIp, serverIp = getClientServerIpFrom(firstPacket[0])
    protocol = getClientServerProtocolFrom(firstPacket[0])
    clientPort, serverPort = getClientServerPortFrom(firstPacket[0], protocol)
    client = settings.PeerData(ip=clientIp, port=clientPort, protocol=protocol)
    server = settings.PeerData(ip=serverIp, port=serverPort, protocol=protocol)
    return client, server

def assertValidPackets(callid, howManyPackets):
    if howManyPackets == 0:
        print("Call-Id: {} not in pcap".format(callid))
        exit(0)

def getDirectionFor(packet, client):
    clientPacket, serverPacket = getClientServerDataFrom(packet)
    if clientPacket.ip != client.ip:
        return settings.SERVER_TO_CLIENT
    if clientPacket.port != client.port:
        return settings.SERVER_TO_CLIENT
    if clientPacket.protocol != client.protocol:
        return settings.SERVER_TO_CLIENT
    return settings.CLIENT_TO_SERVER

#SE SERVER NON SERVE, SERVE TOGLIERLO
def getSipCallFlowFrom(filteredPackets, client):
    callFlow = []
    for packet in filteredPackets:
        direction = getDirectionFor(packet, client)
        callFlow.append(settings.PacketInfo(packet, direction))
    return callFlow

def packetsHandler(packets, callid):
    filteredPackets, howManyPackets = filterPacketsByCallid(packets, callid)
    assertValidPackets(callid, howManyPackets)
    client, server = getClientServerDataFrom(filteredPackets[0])
    callFlow = getSipCallFlowFrom(filteredPackets, client)
    return callFlow
    
def pcapHandler(pcap, callid):
    packets = parsePcap(pcap)
    callFlow = packetsHandler(packets, callid)
    return callFlow
