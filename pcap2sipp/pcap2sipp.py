import helper 

if __name__ == '__main__':
    args = helper.handleArguments()
    helper.checkArgs(vars(args))
    pcap_parsed = helper.parsePcap(args.pcap)
    helper.pcapHandling(pcap_parsed)