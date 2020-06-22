import unittest
from context import sipp_helper
from context import pcap_helper
import scapy.layers.inet as scapy_layers

class Test(unittest.TestCase):

    def setUp(self):
        a = scapy_layers.IP(src="127.0.0.2", dst="127.0.0.5") / scapy_layers.UDP(sport=5050, dport=5010) / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        b = scapy_layers.IP(src="127.0.0.5", dst="127.0.0.2") / scapy_layers.UDP(sport=5010, dport=5050) / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: h000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        firstPacketInfo = pcap_helper.PacketInfo(a, pcap_helper.CLIENT_TO_SERVER)
        secondPacketInfo = pcap_helper.PacketInfo(b, pcap_helper.SERVER_TO_CLIENT)
        self.callFlow = [firstPacketInfo, secondPacketInfo]
        pass

    def tearDown(self):
        pass

    def test_sippHandler_when_typical(self):
        sipp_helper.sippHandler(self.callFlow, "/tmp/")

if __name__ == "__main__":
    unittest.main()
