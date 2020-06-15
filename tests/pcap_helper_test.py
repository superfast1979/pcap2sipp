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
            
    @pytest.mark.skip(reason="does not run on linux")
    def test_pcapHandler_typical(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a,b]
        pcap_helper.pcapHandler(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
            
    def test_isCallIdInPacket_when_True(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        self.assertTrue(pcap_helper.isCallIdInPacket(a, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186"))
        
    def test_isCallIdInPacket_when_False(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        self.assertFalse(pcap_helper.isCallIdInPacket(a, "sdasdasfassasasd47.186"))

    def test_filterPacketsByCallid_when_OnlyOnePacketMatched(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a,b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(1, num_filtered_packets)
        self.assertEqual([a], filtered_packets)
        
    def test_filterPacketsByCallid_when_AllPacketsMatched(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a,b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(2, num_filtered_packets)
        self.assertEqual([a,b], filtered_packets)
        
    def test_filterPacketsByCallid_when_NoPacketsMatched(self):
        a=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: a000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b=scapy_layers.Ether()/scapy_layers.IP()/scapy_layers.UDP()/"INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: b000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        c = [a,b]
        filtered_packets, num_filtered_packets = pcap_helper.filterPacketsByCallid(c, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
        self.assertEqual(0, num_filtered_packets)
        self.assertEqual([], filtered_packets)

if __name__ == "__main__":
    unittest.main()