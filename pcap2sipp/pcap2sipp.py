import helper 
import pcap_helper

if __name__ == '__main__':
    args = helper.handleArguments()
    helper.checkArgs(vars(args))
    pcap_helper.pcapHandler(args.pcap, args.callid)