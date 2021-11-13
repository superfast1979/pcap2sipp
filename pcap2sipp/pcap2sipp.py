import helper 
import pcap_helper
import sipp_helper
import settings

if __name__ == '__main__':
    settings.init()
    args = helper.handleArguments()
    helper.checkArgs(vars(args))
    callFlowFilteredByCallid = pcap_helper.pcapHandler(args.pcap, args.callid)
    sipp_helper.sippHandler(callFlowFilteredByCallid, args.path)
    