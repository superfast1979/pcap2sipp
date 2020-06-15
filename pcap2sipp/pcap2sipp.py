import helper 
import pcap_helper

if __name__ == '__main__':
    args = helper.handleArguments()
    helper.checkArgs(vars(args))
    packets = pcap_helper.parsePcap(args.pcap)
    pcap_helper.pcapHandler(packets, args.callid)