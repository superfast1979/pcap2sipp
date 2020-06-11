import argparse
import os
import sys
from IPy import IP

def handleArguments():
    parser = argparse.ArgumentParser(prog="pcap2sipp.py", description="pcap file to sipp scenarios")
    parser.add_argument('pcap', help='file pcap to analyze')
    parser.add_argument('path', help='path to store sipp scenarios')
    parser.add_argument('src', help='client ip in pcap file')
    parser.add_argument('dst', help='server ip in pcap file')
    args = parser.parse_args()
    return args

def checkArgs(args):
    if not os.path.isdir(args['path']):
        raise Exception("path not found")
    try:
        IP(args['src'])
    except:
        raise Exception("src not a valid ip")
    try:
        IP(args['dst'])
    except:
        raise Exception("dst not a valid ip")
    if not os.path.isfile(args['pcap']):
        raise Exception("no pcap found")

if __name__ == '__main__':
    args = handleArguments()
    checkArgs(vars(args))
    print("end")