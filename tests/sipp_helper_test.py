import unittest
from context import sipp_helper
from context import pcap_helper
import scapy.layers.inet as scapy_layers
from string import Template
from testfixtures import tempdir, compare
import pytest

try:
    # python 3.4+ should use builtin unittest.mock not mock package
    from unittest.mock import patch
except ImportError:
    from mock import patch
    
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

    @pytest.mark.skip(reason="does not run on linux")
    def test_sippHandler_when_typical(self):
        pass
#         sipp_helper.sippHandler(self.callFlow, "./")

    @tempdir()
    def test_writeScenarioHeader_when_typical(self, dir):
        sipp_helper.writeScenarioHeader(dir.path,'client_scenario.xml')
        compare(dir.read('client_scenario.xml'), b'<?xml version="1.0" encoding="ISO-8859-1"?>\n<scenario name="client_scenario.xml">\n',show_whitespace=True)
        
    @tempdir()
    def test_writeScenarioFooter_when_typical(self, dir):
        sipp_helper.writeScenarioFooter(dir.path,'client_scenario.xml')
        compare(dir.read('client_scenario.xml'), b'  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n</scenario>\n',show_whitespace=True)

if __name__ == "__main__":
    unittest.main()
