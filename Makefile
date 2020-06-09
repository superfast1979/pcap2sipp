init:
	mkdir -p /tmp/pcap2sipp_makefile
	cp -pr * /tmp/pcap2sipp_makefile/
	cd /tmp/pcap2sipp_makefile/ && virtualenv . && source bin/activate && pip install -U -r requirements.txt

test:
	cd /tmp/pcap2sipp_makefile/ && pytest tests

.PHONY: init test