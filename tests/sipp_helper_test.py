import unittest
from context import sipp_helper
from context import pcap_helper
from context import settings
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
        firstPacketInfo = settings.PacketInfo(a, settings.CLIENT_TO_SERVER)
        secondPacketInfo = settings.PacketInfo(b, settings.SERVER_TO_CLIENT)
        self.callFlow = [firstPacketInfo, secondPacketInfo]
        pass

    def tearDown(self):
        pass

    @pytest.mark.skip(reason="does not run on linux")
    def test_sippHandler_when_typical(self):
        pass
#         sipp_helper.sippHandler(self.callFlow, "./")

    def test_isResponse_when_response(self):
        self.assertTrue(sipp_helper.isResponse("sip/2.0 200 ok"))
        
    def test_isResponse_when_request(self):
        self.assertFalse(sipp_helper.isResponse("invite sip:+390289279987@fastweb.it;user=phone sip/2.0"))
        
    def test_parseFirstLineFrom_when_request(self):
        value, method = sipp_helper.parseFirstLineFrom("invite sip:+390289279987@fastweb.it;user=phone sip/2.0\r\nvia: sip/2.0/udp 10.252.47.107:5060;branch=z9hg4bkdtv49tkbcc37nimia53bvq9dt5\r\nto: <sip:+390289279987@fastweb.it;user=phone>\r\n")
        self.assertEqual(settings.REQUEST, value)
        self.assertEqual("invite", method)
        
    def test_parseFirstLineFrom_when_response(self):
        value, method = sipp_helper.parseFirstLineFrom("sip/2.0 100 trying\r\nvia: sip/2.0/udp 10.252.47.107:5060;branch=z9hg4bkdtv49tkbcc37nimia53bvq9dt5\r\nto: <sip:+390289279987@fastweb.it;user=phone>\r\n")
        self.assertEqual(settings.RESPONSE, value)
        self.assertEqual("100", method)
        
    def test_getSipMsgAndDirection_when_typical(self):
        packet = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        packetInfo = settings.PacketInfo(packet, settings.CLIENT_TO_SERVER)
        sipMsg, direction = sipp_helper.getSipMsgAndDirection(packetInfo)
        self.assertEqual(settings.CLIENT_TO_SERVER, direction)
        self.assertEqual("options sip:fw-nms-2:5060 sip/2.0\r\nvia: sip/2.0/udp 10.252.47.186:5060;branch=z9hg4bk0g04430050bgj18o80j1\r\nto: sip:ping@fw-nms-2\r\nfrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\ncall-id: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\ncseq: 14707 options\r\nmax-forwards: 0\r\ncontent-length: 0\r\n\r\n", sipMsg)

    def test_replaceHeaderSippForServer_when_typical(self):
        packet = scapy_layers.UDP() / "INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nRecord-Route: sip:138.132.1.2\r\nContact: sip:contact@192.168.100.1\r\nCSeq: 14707 INVITE\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        sipMsg = sipp_helper.replaceHeaderSippForServer(sipMsg)
        self.assertEqual(-1, sipMsg.find("via:"))
        self.assertEqual(-1, sipMsg.find("call-id:"))
        self.assertEqual(-1, sipMsg.find("from:"))
        self.assertEqual(-1, sipMsg.find("to:"))
        self.assertEqual(-1, sipMsg.find("cseq:"))
        self.assertEqual(-1, sipMsg.find("contact:"))
        self.assertEqual(-1, sipMsg.find("record-route:"))
        
        self.assertNotEqual(-1, sipMsg.find("[last_Call-ID:]"))
        self.assertNotEqual(-1, sipMsg.find("[last_From:]"))
        self.assertNotEqual(-1, sipMsg.find("[last_CSeq:]"))
        self.assertNotEqual(-1, sipMsg.find("[last_To:];tag=[call_number]"))
        self.assertNotEqual(-1, sipMsg.find("[last_Record-route:]"))
        self.assertNotEqual(-1, sipMsg.find("Contact: <sip:[local_ip]:[local_port];transport=[transport]>"))

    @tempdir()
    def test_writeScenarioHeader_when_typical(self, dir):
        sipp_helper.writeScenarioHeader(dir.path, 'client_scenario.xml')
        compare(dir.read('client_scenario.xml'), b'<?xml version="1.0" encoding="ISO-8859-1"?>\n<scenario name="scenario">\n', show_whitespace=True)
        
    @tempdir()
    def test_writeScenarioFooter_when_typical(self, dir):
        sipp_helper.writeScenarioFooter(dir.path, 'client_scenario.xml')
        compare(dir.read('client_scenario.xml'), b'  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n</scenario>\n', show_whitespace=True)
        
    @tempdir()
    def test_writeSendMessageClient_when_typical(self, dir):
        sipp_helper.writeSendMessageClient(dir.path, 'client_scenario.xml', "mockSipMsgClient")
        compare(dir.read('client_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\nmockSipMsgClient\n      ]]>\n  </send>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writeSendMessageServer_when_typical(self, dir):
        sipp_helper.writeSendMessageServer(dir.path, 'server_scenario.xml', "mockSipMsgServer")
        compare(dir.read('server_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\nmockSipMsgServer\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)

    @tempdir()
    def test_writeRecvMessageResponse_when_typical(self, dir):
        sipp_helper.writeRecvMessageResponse(dir.path, 'server_scenario.xml', "481")
        compare(dir.read('server_scenario.xml'), b'  <recv response="481"/>\n\n', show_whitespace=True)

    @tempdir()
    def test_writeRecvMessageRequest_when_invite(self, dir):
        sipp_helper.writeRecvMessageRequest(dir.path, 'server_scenario.xml', "invite")
        compare(dir.read('server_scenario.xml'), b'  <recv request="invite" rrs="true" crlf="true"/>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writeRecvMessageRequest_when_not_invite(self, dir):
        sipp_helper.writeRecvMessageRequest(dir.path, 'server_scenario.xml', "cancel")
        compare(dir.read('server_scenario.xml'), b'  <recv request="cancel"/>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writePacketClientToServer_when_request_invite(self, dir):
        packet = scapy_layers.UDP() / "INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketClientToServer(dir.path, sipMsg, settings.REQUEST, "invite")
        
        compare(dir.read('client_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\ninvite sip:fw-nms-2:5060 sip/2.0\r\nvia: sip/2.0/udp 10.252.47.186:5060;branch=z9hg4bk0g04430050bgj18o80j1\r\nto: sip:ping@fw-nms-2\r\nfrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\ncall-id: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\ncseq: 14707 options\r\nmax-forwards: 0\r\ncontent-length: 0\r\n\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('server_scenario.xml'), b'  <recv request="invite" rrs="true" crlf="true"/>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writePacketClientToServer_when_request_not_invite(self, dir):
        packet = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketClientToServer(dir.path, sipMsg, settings.REQUEST, "options")
        
        compare(dir.read('client_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\noptions sip:fw-nms-2:5060 sip/2.0\r\nvia: sip/2.0/udp 10.252.47.186:5060;branch=z9hg4bk0g04430050bgj18o80j1\r\nto: sip:ping@fw-nms-2\r\nfrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\ncall-id: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\ncseq: 14707 options\r\nmax-forwards: 0\r\ncontent-length: 0\r\n\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('server_scenario.xml'), b'  <recv request="options"/>\n\n', show_whitespace=True)

    @tempdir()
    def test_writePacketClientToServer_when_response(self, dir):
        packet = scapy_layers.UDP() / "sip/2.0 100 trying\r\nvia: sip/2.0/udp 10.252.47.107:5060;branch=z9hg4bkdtv49tkbcc37nimia53bvq9dt5\r\nto: <sip:+390289279987@fastweb.it;user=phone>\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketClientToServer(dir.path, sipMsg, settings.RESPONSE, "100")
        
        compare(dir.read('client_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\nsip/2.0 100 trying\r\nvia: sip/2.0/udp 10.252.47.107:5060;branch=z9hg4bkdtv49tkbcc37nimia53bvq9dt5\r\nto: <sip:+390289279987@fastweb.it;user=phone>\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('server_scenario.xml'), b'  <recv response="100"/>\n\n', show_whitespace=True)

    @tempdir()
    def test_writePacketServerToClient_when_request_invite(self, dir):
        packet = scapy_layers.UDP() / "INVITE sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketServerToClient(dir.path, sipMsg, settings.REQUEST, "invite")
        
        compare(dir.read('server_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\ninvite sip:fw-nms-2:5060 sip/2.0\r\n[last_Via:]\r\n[last_To:];tag=[call_number]\r\n[last_From:]\r\n[last_Call-ID:]\r\n[last_CSeq:]\r\nmax-forwards: 0\r\ncontent-length: 0\r\n\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('client_scenario.xml'), b'  <recv request="invite" rrs="true" crlf="true"/>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writePacketServerToClient_when_request_not_invite(self, dir):
        packet = scapy_layers.UDP() / "OPTIONS sip:Fw-NMS-2:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 10.252.47.186:5060;branch=z9hG4bK0g04430050bgj18o80j1\r\nTo: sip:ping@Fw-NMS-2\r\nFrom: <sip:ping@10.252.47.186>;tag=g000000q5m200-jbe0000\r\nCall-ID: g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186\r\nCSeq: 14707 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketServerToClient(dir.path, sipMsg, settings.REQUEST, "options")
        
        compare(dir.read('server_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\noptions sip:fw-nms-2:5060 sip/2.0\r\n[last_Via:]\r\n[last_To:];tag=[call_number]\r\n[last_From:]\r\n[last_Call-ID:]\r\n[last_CSeq:]\r\nmax-forwards: 0\r\ncontent-length: 0\r\n\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('client_scenario.xml'), b'  <recv request="options"/>\n\n', show_whitespace=True)
        
    @tempdir()
    def test_writePacketServerToClient_when_response(self, dir):
        packet = scapy_layers.UDP() / "sip/2.0 100 trying\r\nvia: sip/2.0/udp 10.252.47.107:5060;branch=z9hg4bkdtv49tkbcc37nimia53bvq9dt5\r\nto: <sip:+390289279987@fastweb.it;user=phone>\r\n\r\n"
        sipMsg = packet.load.lower().decode('utf-8')
        
        sipp_helper.writePacketServerToClient(dir.path, sipMsg, settings.RESPONSE, "100")
        
        compare(dir.read('server_scenario.xml'), b'  <pause milliseconds="50"/>\n\n  <send>\n      <![CDATA[\nsip/2.0 100 trying\r\n[last_Via:]\r\n[last_To:];tag=[call_number]\r\n\r\n\n      ]]>\n  </send>\n\n', show_whitespace=True)
        compare(dir.read('client_scenario.xml'), b'  <recv response="100"/>\n\n', show_whitespace=True)


if __name__ == "__main__":
    unittest.main()
