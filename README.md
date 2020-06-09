[![Build status](https://api.travis-ci.org/superfast1979/pcap2sipp.svg?branch=master)](https://travis-ci.org/superfast1979)

# pcap2sipp
Simple purpose: translate pcap sip messages to sipp call flow.

Read from a pcap file all sip messages between two peers, identified from ip_src and ip_dst parameter and generates two sipp xml files, typically named client_scenario.xml and server_scenario.xml


Table of Contents
-----------------

  * [Requirements](#requirements)
  * [Usage](#usage)
  * [Contributing](#contributing)
  * [License](#license)

Requirements
------------
pcap2sipp:

  * [Python][python2] 2.7+

[python2]: https://www.python.org/download/releases/2.7/

Usage
------------
python /path/to/pcap2sipp/pcap2sipp -i /path/to/pcap_file.pcap -o /path/to/sipp_files/ -ip_src 138.132.111.49 -ip_dst 138.132.112.79

License
-------

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Contributing
------------

To contribute to pcap2sipp, clone this repo locally and commit your code on a separate branch. Please write unit tests for your code before opening a pull-request:

```sh
make test  # run all unit tests
```

