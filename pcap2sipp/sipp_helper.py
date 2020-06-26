import os

def writeScenarioHeader(path, file):
    with open(os.path.join(path,file), "wb") as scenario:
        scenario.write(bytes('<?xml version="1.0" encoding="ISO-8859-1"?>\n').encode())
        scenario.write(bytes('<scenario name="{}">\n'.format(file)).encode())
        
def writeScenarioFooter(path, file):
    with open(os.path.join(path, file), "a+b") as scenario:
        scenario.write(bytes('  <ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>\n').encode())
        scenario.write(bytes('  <CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>\n').encode())
        scenario.write(bytes('</scenario>\n').encode())
        
def sippHandler(callFlowFilteredByCallid, path):
    writeScenarioHeader(path, "client_scenario.xml")
    writeScenarioFooter(path, "client_scenario.xml")
    writeScenarioHeader(path, "server_scenario.xml")
    writeScenarioFooter(path, "server_scenario.xml")
    pass