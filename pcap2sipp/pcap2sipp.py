'''
Created on 5 giu 2020

@author: augello
'''
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="pcap2sipp.py", description="pcap file to sipp scenarios")
    parser.add_argument('pcap', help='file pcap to analyze')
    parser.add_argument('path', help='path to store sipp scenarios')
    parser.add_argument('src', help='client ip in pcap file')
    parser.add_argument('dst', help='server ip in pcap file')
    
    args = parser.parse_args()
    if args.include:
        print("pcap %s" % (args.include))
    if args.output:
        print("output %s" % (args.output))
    if args.ip_src:
        print("ip_src %s" % (args.ip_src))
    if args.ip_dst:
        print("ip_dst %s" % (args.ip_dst))
