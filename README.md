[![Build status](https://api.travis-ci.org/superfast1979/pcap2sipp.svg?branch=master)](https://travis-ci.org/superfast1979)
[![Python version support](https://img.shields.io/badge/python-2.7%20%7C%203.8-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![codecov.io](https://codecov.io/gh/superfast1979/pcap2sipp/coverage.svg?branch=master)](https://codecov.io/gh/superfast1979/pcap2sipp) 
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

# pcap2sipp
Simple purpose: translate pcap sip messages to sipp call flow.

Read from a pcap file all sip messages between two peers, identified from ip_src and ip_dst parameters and then it generates two sipp xml files, typically named client_scenario.xml and server_scenario.xml


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
  * [Scapy][scapy] 2

[python2]: https://www.python.org/download/releases/2.7/
[scapy]: https://scapy.readthedocs.io/en/latest/index.html

Usage
------------
python /path/to/pcap2sipp/pcap2sipp.py pcap /path/to/pcap_file.pcap path /path/to/sipp_files/ src 138.132.111.49 dst 138.132.112.79

License
-------

pcap2sipp is licensed under the [GPL](#) license.
Copyright &copy; 2020, Augello Marco

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Contributing
------------

To contribute to pcap2sipp, clone this repo locally and commit your code on a separate branch. Please write unit tests for your code before opening a pull-request:

```sh
make test  # run all unit tests
```

