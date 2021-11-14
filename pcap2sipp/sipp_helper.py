import os
import settings
import sys

def replaceHeaderSippForServer(sipMsg):
    lines_modified = []
    lines = sipMsg.splitlines(False)
    for line in lines:
        if line.startswith("via:"):
            line = "[last_Via:]"
        if line.startswith("call-id:"):
            line = "[last_Call-ID:]"
        if line.startswith("from:"):
            line = "[last_From:]"
        if line.startswith("cseq:"):
            line = "[last_CSeq:]"
        if line.startswith("to:"):
            line = "[last_To:];tag=[call_number]"
        if line.startswith("record-route:"):
            line = "[last_Record-route:]"
        if line.startswith("contact:"):
            line = "Contact: <sip:[local_ip]:[local_port];transport=[transport]>"
        lines_modified.append(line)
    return "\r\n".join(lines_modified)


def writeScenarioHeader(path, file):
    with open(os.path.join(path, file), "wb") as scenario:
        scenario.write(bytes(b'<?xml version="1.0" encoding="ISO-8859-1"?>\n'))
        scenario.write(bytes(b'<scenario name="scenario">\n'))

        
def writeScenarioFooter(path, file):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n'))
        scenario.write(bytes(b'  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n'))
        scenario.write(bytes(b'</scenario>\n'))


def bytes_encoding(strings):
    if sys.version_info[0] == 3:
        return bytes(strings, encoding='utf8')
    else:
        return bytes(strings)


def writeSendMessageCommon(path, file, sipMsg):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <pause milliseconds="50"/>\n\n'))
        scenario.write(bytes(b'  <send>\n'))
        scenario.write(bytes(b'      <![CDATA[\n'))
        sipMsg_encoded = bytes_encoding(sipMsg)
        scenario.write(bytes(b'' + sipMsg_encoded + '\n'))
        scenario.write(bytes(b'      ]]>\n'))
        scenario.write(bytes(b'  </send>\n\n'))

        
def writeSendMessageClient(path, file, sipMsg):
    writeSendMessageCommon(path, file, sipMsg)


def writeSendMessageServer(path, file, sipMsg):
    sipMsg = replaceHeaderSippForServer(sipMsg)
    writeSendMessageCommon(path, file, sipMsg)

        
def writeRecvMessageRequest(path, file, method):
    with open(os.path.join(path, file), "a+b") as scenario:
        method_encoded = bytes_encoding(method)
        if method == "invite":
            scenario.write(bytes(b'  <recv request="' + method_encoded + b'" rrs="true" crlf="true"/>\n\n'))
        else:
            scenario.write(bytes(b'  <recv request="' + method_encoded + b'"/>\n\n'))

            
def writeRecvMessageResponse(path, file, response):
    with open(os.path.join(path, file), "a+b") as scenario:
        response_encoded = bytes_encoding(response)
        scenario.write(bytes(b'  <recv response="' + response_encoded + b'"/>\n\n'))

        
def isResponse(firstLine):
    if firstLine.startswith("sip/2.0"):
        return True
    return False


def parseFirstLineFrom(sipMsg):
    lines = sipMsg.split("\r\n")
    if isResponse(lines[0]):
        return settings.RESPONSE, lines[0].split(" ")[1]
    else:
        return settings.REQUEST, lines[0].split(" ")[0]

    
def sippHandler(callFlowFilteredByCallid, path):
    writeScenarioHeader(path, "client_scenario.xml")
    writeScenarioHeader(path, "server_scenario.xml")
    for packetInfo in callFlowFilteredByCallid:
        sipMsg = packetInfo.packet.load.lower().decode('utf-8')
        messageType, method_or_response = parseFirstLineFrom(sipMsg)
        direction = packetInfo.direction
        if direction == settings.CLIENT_TO_SERVER:
            writeSendMessageClient(path, "client_scenario.xml", sipMsg)
            if messageType == settings.REQUEST:
                writeRecvMessageRequest(path, "server_scenario.xml", method_or_response)
            else:
                writeRecvMessageResponse(path, "server_scenario.xml", method_or_response)
        else:
            writeSendMessageServer(path, "server_scenario.xml", sipMsg)
            if messageType == settings.REQUEST:
                writeRecvMessageRequest(path, "client_scenario.xml", method_or_response)
            else:
                writeRecvMessageResponse(path, "client_scenario.xml", method_or_response)
    writeScenarioFooter(path, "client_scenario.xml")
    writeScenarioFooter(path, "server_scenario.xml")
    pass
