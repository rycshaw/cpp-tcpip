#g++ -std=c++11 -c pcap_file_reader.cpp -I ..

g++ -g -std=c++11 hexdump.cpp dump_pcap_main.cpp pcap_file_reader.cpp -o dump_pcap -I ..

