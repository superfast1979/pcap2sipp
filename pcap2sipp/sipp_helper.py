import os
import settings
from __builtin__ import True

def writeScenarioHeader(path, file):
    with open(os.path.join(path,file), "wb") as scenario:
        scenario.write(bytes(b'<?xml version="1.0" encoding="ISO-8859-1"?>\n'))
        scenario.write(bytes(b'<scenario name="scenario">\n'))
        
def writeScenarioFooter(path, file):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n'))
        scenario.write(bytes(b'  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n'))
        scenario.write(bytes(b'</scenario>\n'))
        
def writeSendMessage(path, file, sipMsg):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <send>\n'))
        scenario.write(bytes(b'      <![CDATA[\n'))
        scenario.write(bytes(b'{}\n').format(sipMsg))
        scenario.write(bytes(b'      ]]>\n'))
        scenario.write(bytes(b'  </send>\n\n'))
        
def writeRecvMessageRequest(path, file, method):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <recv request="{}"/>\n\n'.format(method)))
        
def writeRecvMessageResponse(path, file, response):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <recv response="{}"/>\n\n'.format(response)))
        
def isResponse(firstLine):
    if firstLine.startswith("sip/2.0"):
        return True
    return False

REQUEST = 1
RESPONSE = 2

def parseFirstLineFrom(sipMsg):
    lines = sipMsg.split("\r\n")
    if isResponse(lines[0]):
        return RESPONSE, lines[0].split(" ")[1]
    else:
        return REQUEST, lines[0].split(" ")[0]
    
def sippHandler(callFlowFilteredByCallid, path):
    writeScenarioHeader(path, "client_scenario.xml")
    writeScenarioHeader(path, "server_scenario.xml")
    for packetInfo in callFlowFilteredByCallid:
        sipMsg = packetInfo.packet.load.lower().decode('utf-8')
        messageType, method_or_response = parseFirstLineFrom(sipMsg)
        direction = packetInfo.direction
        if direction == settings.CLIENT_TO_SERVER:
            writeSendMessage(path, "client_scenario.xml", sipMsg)
            if messageType == REQUEST:
                writeRecvMessageRequest(path, "server_scenario.xml", method_or_response)
            else:
                writeRecvMessageResponse(path, "server_scenario.xml", method_or_response)
        else:
            writeSendMessage(path, "server_scenario.xml", sipMsg)
            if messageType == REQUEST:
                writeRecvMessageRequest(path, "client_scenario.xml", method_or_response)
            else:
                writeRecvMessageResponse(path, "client_scenario.xml", method_or_response)
    writeScenarioFooter(path, "client_scenario.xml")
    writeScenarioFooter(path, "server_scenario.xml")
    pass