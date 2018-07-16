all: dump_pcap

PCAP_SRCS= pcap_file_reader.cpp

PCAP_HEADERS= packet_headers.hpp \
	pcap_file_reader.hpp

UTIL_SRCS=../util/hexdump.cpp

UTIL_HEADERS= ../util/hexdump.hpp \
	../util/throw_assert.hpp

dump_pcap: dump_pcap_main.cpp $(PCAP_SRCS) $(PCAP_HEADERS) $(UTIL_SRCS) $(UTIL_HEADERS)
	g++ -g -std=c++11 dump_pcap_main.cpp -I .. $(PCAP_SRCS) $(UTIL_SRCS) -o dump_pcap

clean:
	rm -f dump_pcap
