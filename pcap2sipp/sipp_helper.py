import os
import settings

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
        
def sippHandler(callFlowFilteredByCallid, path):
    writeScenarioHeader(path, "client_scenario.xml")
    writeScenarioHeader(path, "server_scenario.xml")
    for packetInfo in callFlowFilteredByCallid:
        sipMsg = packetInfo.packet.load.lower().decode('utf-8')
        direction = packetInfo.direction
        if direction == settings.CLIENT_TO_SERVER:
            writeSendMessage(path, "client_scenario.xml", sipMsg)
            #writeRecvMessage(path, "server_scenario.xml", sipMsg)
        else:
            writeSendMessage(path, "server_scenario.xml", sipMsg)
            #writeRecvMessage(path, "client_scenario.xml", sipMsg)
    writeScenarioFooter(path, "client_scenario.xml")
    writeScenarioFooter(path, "server_scenario.xml")
    pass