import argparse
import os

def handleArguments():
    parser = argparse.ArgumentParser(prog="pcap2sipp.py", description="pcap file to sipp scenarios")
    parser.add_argument('pcap', help='file pcap to analyze')
    parser.add_argument('path', help='path to store sipp scenarios')
    parser.add_argument('callid', help='sip session callid')
    args = parser.parse_args()
    return args

def checkPath(path):
    if not os.path.isdir(path):
        raise Exception("path not found")
    
def checkPcap(pcap):
    if not os.path.isdir(pcap):
        raise Exception("pcap not found")
    
def checkArgs(args):
    checkPath(args['path'])
    checkPcap(args['pcap'])

