[![Build status](https://api.travis-ci.org/superfast1979/pcap2sipp.svg?branch=master)](https://travis-ci.org/superfast1979)

# pcap2sipp
Simple purpose: translate pcap sip messages to sipp call flow.

Read from a pcap file all sip messages between two peers, identified from ip_src and ip_dst parameter and generates two sipp xml files, typically named client_scenario.xml and server_scenario.xml

### Usage
python /path/to/pcap2sipp/pcap2sipp -i /path/to/pcap_file.pcap -o /path/to/sipp_files/ -ip_src 138.132.111.49 -ip_dst 138.132.112.79


