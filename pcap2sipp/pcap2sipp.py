import argparse


def printArgs(args):
    print "pcap %s" % (args.pcap)
    print "output %s" % (args.path)
    print "ip_src %s" % (args.src)
    print "ip_dst %s" % (args.dst)
    
def handleArguments():
    parser = argparse.ArgumentParser(prog="pcap2sipp.py", description="pcap file to sipp scenarios")
    parser.add_argument('pcap', help='file pcap to analyze')
    parser.add_argument('path', help='path to store sipp scenarios')
    parser.add_argument('src', help='client ip in pcap file')
    parser.add_argument('dst', help='server ip in pcap file')
    args = parser.parse_args()
    printArgs(args)
    return args

if __name__ == '__main__':
    args = handleArguments()
