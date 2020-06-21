import unittest
from context import pcap_helper
import pytest
import scapy.layers.inet as scapy_layers


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @pytest.mark.skip(reason="does not run on linux")
    def test_parsePcap_typical(self):
        pcap_helper.parsePcap("./example.pcap")

    def test_isCallIdInPacket_when_True(self):
        a = scapy_layers.Ether() / scapy_layers.IP() / scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        self.assertTrue(pcap_helper.isCallIdInPacket(a, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186"))
        
    def test_isCallIdInPacket_when_False(self):
        a = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        self.assertFalse(pcap_helper.isCallIdInPacket(a, "sdasdasfassasasd47.186"))

    def test_filterPacketsByCallid_when_OnlyOnePacketMatched(self):
        a = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a, b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(1, num_filtered_packets)
        self.assertEqual([a], filtered_packets)
        
    def test_filterPacketsByCallid_when_AllPacketsMatched(self):
        a = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.UDP() / "INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a, b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(2, num_filtered_packets)
        self.assertEqual([a, b], filtered_packets)
        
    def test_filterPacketsByCallid_when_NoPacketsMatched(self):
        a = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: a000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.UDP() / "INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: b000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a, b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(0, num_filtered_packets)
        self.assertEqual([], filtered_packets)

    def test_assertValidPackets_when_noPacketsMatched(self):
        with self.assertRaises(SystemExit) as se:
            pcap_helper.assertValidPackets("sdas0q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186", 0)
        self.assertEqual(se.exception.code, 0)

    def test_assertValidPackets_when_OnePacketMatched(self):
        try:
            pcap_helper.assertValidPackets("sdas0q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186", 1)
        except:
            pytest.fail("no exception expected")

    def test_getClientIpFrom_when_IPV4(self):
        ipv4_packet = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5")
        ip_client, ip_server = pcap_helper.getClientServerIpFrom(ipv4_packet)
        self.assertEqual("127.0.0.2", ip_client)
        self.assertEqual("127.0.0.5", ip_server)
        
    def test_getClientServerPortFrom_when_UDP(self):
        udp_packet = scapy_layers.UDP(sport=5070, dport=5080)
        client_port, server_port = pcap_helper.getClientServerPortFrom(udp_packet, scapy_layers.UDP)
        self.assertEqual(5070, client_port)
        self.assertEqual(5080, server_port)
        
    def test_getClientServerPortFrom_when_TCP(self):
        tcp_packet = scapy_layers.TCP(sport=5050, dport=5010)
        client_port, server_port = pcap_helper.getClientServerPortFrom(tcp_packet, scapy_layers.TCP)
        self.assertEqual(5050, client_port)
        self.assertEqual(5010, server_port)
        
    def test_getClientServerProtocolFrom_when_TCP(self):
        tcp_packet = scapy_layers.TCP()
        protocol = pcap_helper.getClientServerProtocolFrom(tcp_packet)
        self.assertEqual(scapy_layers.TCP, protocol)
        
    def test_getClientServerProtocolFrom_when_UDP(self):
        udp_packet = scapy_layers.UDP()
        protocol = pcap_helper.getClientServerProtocolFrom(udp_packet)
        self.assertEqual(scapy_layers.UDP, protocol)
        
    def test_getClientServerProtocolFrom_when_ICMP(self):
        icmp_packet = scapy_layers.ICMP()
        with self.assertRaises(SystemExit) as se:
            protocol = pcap_helper.getClientServerProtocolFrom(icmp_packet)
        self.assertEqual(se.exception.code, 0)
        
    def test_getClientServerDataFrom_when_TCP(self):
        tcp_packet = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.TCP(sport=5050, dport=5010)
        client, server = pcap_helper.getClientServerDataFrom(tcp_packet)
        self.assertEqual(client.ip, "127.0.0.2")
        self.assertEqual(client.port, 5050)
        self.assertEqual(client.protocol, scapy_layers.TCP)
        self.assertEqual(server.ip, "127.0.0.5")
        self.assertEqual(server.port, 5010)
        self.assertEqual(server.protocol, scapy_layers.TCP)
        
    def test_getClientServerDataFrom_when_UDP(self):
        tcp_packet = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.UDP(sport=5050, dport=5010)
        client, server = pcap_helper.getClientServerDataFrom(tcp_packet)
        self.assertEqual(client.ip, "127.0.0.2")
        self.assertEqual(client.port, 5050)
        self.assertEqual(client.protocol, scapy_layers.UDP)
        self.assertEqual(server.ip, "127.0.0.5")
        self.assertEqual(server.port, 5010)
        self.assertEqual(server.protocol, scapy_layers.UDP)
        
    def test_getDirectionFor_when_CLIENT_TO_SERVER(self):
        packet = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.UDP(sport=5050, dport=5010)
        client = pcap_helper.PeerData(ip="127.0.0.2", port=5050, protocol=scapy_layers.UDP)
        direction = pcap_helper.getDirectionFor(packet, client)
        self.assertEqual(pcap_helper.CLIENT_TO_SERVER, direction)
        
    def test_getDirectionFor_when_SERVER_TO_CLIENT(self):
        packet = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.TCP(sport=5050, dport=5010)
        client = pcap_helper.PeerData(ip="127.0.0.5", port=5010, protocol=scapy_layers.TCP)
        direction = pcap_helper.getDirectionFor(packet, client)
        self.assertEqual(pcap_helper.SERVER_TO_CLIENT, direction)
        
    def test_getSipCallFlowFrom_when_simpleScenario(self):
        a = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.UDP(sport=5050, dport=5010) / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.IP(src="127.0.0.5", dst="127.0.0.2") / scapy_layers.UDP(sport=5010, dport=5050) / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        packets = [a, b]
        client = pcap_helper.PeerData(ip="127.0.0.2", port=5050, protocol=scapy_layers.UDP)
        
        callFlow = pcap_helper.getSipCallFlowFrom(packets, client)

        self.assertEqual(2, len(callFlow))
        firstPacketInfo = pcap_helper.PacketInfo(a, pcap_helper.CLIENT_TO_SERVER)
        self.assertEqual(firstPacketInfo, callFlow[0])
        secondPacketInfo = pcap_helper.PacketInfo(b, pcap_helper.SERVER_TO_CLIENT)
        self.assertEqual(secondPacketInfo, callFlow[1])

    @pytest.mark.skip(reason="does not run on linux")
    def test_pcapHandler_typical(self):
        a = scapy_layers.IP() / scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.IP() / scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a, b]
        pcap_helper.pcapHandler(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        
    @pytest.mark.skip(reason="does not run on linux")
    def test_pcapHandler_when_NoPacketsMatched(self):
        a = scapy_layers.IP() / scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.IP() / scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a, b]
        with self.assertRaises(SystemExit) as se:
            pcap_helper.pcapHandler(c, "sdas0q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(se.exception.code, 0)

        
if __name__ == "__main__":
    unittest.main()
