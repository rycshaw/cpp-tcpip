all: PCAP

clean:
	$(MAKE) -C pcap clean

PCAP:
	cd pcap && $(MAKE)
