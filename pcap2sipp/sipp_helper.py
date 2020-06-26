import os

def writeScenarioHeader(path, file):
    with open(os.path.join(path,file), "wb") as scenario:
        scenario.write(bytes(b'<?xml version="1.0" encoding="ISO-8859-1"?>\n'))
        scenario.write(bytes(b'<scenario name="{}">\n'.format(file)))
        
def writeScenarioFooter(path, file):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes(b'  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n'))
        scenario.write(bytes(b'  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n'))
        scenario.write(bytes(b'</scenario>\n'))
        
def sippHandler(callFlowFilteredByCallid, path):
    writeScenarioHeader(path, "client_scenario.xml")
    writeScenarioFooter(path, "client_scenario.xml")
    writeScenarioHeader(path, "server_scenario.xml")
    writeScenarioFooter(path, "server_scenario.xml")
    pass