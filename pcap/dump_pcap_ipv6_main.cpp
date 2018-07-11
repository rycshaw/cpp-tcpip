#include <iostream>
#include <sstream>

#include "pcap/pcap_file_reader.hpp"

namespace pcap {

void dumpIpV4Packet(const pcap::PcapPacketHeader_t &packet_header,
                    const pcap::EthernetHeader_t &ethernet_header)
{
    RT_ASSERT(pcap::EtherType_e(ethernet_header.getEtherTypeHbo()) == EtherType_e::kIpV4, "Expected ethertype == ipv4");
    const IpV4Header_t *ip_header =
        reinterpret_cast<const IpV4Header_t *>(ethernet_header.getPayloadPtr());
    std::cout << "IpV4: protocol: " << static_cast<int>(ip_header->protocol)
              << ", IpPayloadLengthBytes: " << ip_header->getPayloadLengthBytesHbo() << std::endl;
}

void dumpIpV6Packet(const pcap::PcapPacketHeader_t &packet_header,
                    const pcap::EthernetHeader_t &ethernet_header)
{
    RT_ASSERT(pcap::EtherType_e(ethernet_header.getEtherTypeHbo()) == EtherType_e::kIpV6, "Expected ethertype == ipv6");
    const IpV6Header_t *ip_header =
        reinterpret_cast<const IpV6Header_t *>(ethernet_header.getPayloadPtr());
    std::cout << "IpV6: next_header: " << static_cast<int>(ip_header->next_header)
              << ", IpPayloadLengthBytes: " << ip_header->getPayloadLengthBytesHbo() << std::endl;
}

void dumpPacket(const pcap::PcapPacketHeader_t &packet_header,
                const pcap::EthernetHeader_t &ethernet_header)
{
    switch (pcap::EtherType_e(ethernet_header.getEtherTypeHbo())) {
        case pcap::EtherType_e::kIpV4:
            dumpIpV4Packet(packet_header, ethernet_header);
            break;
        case pcap::EtherType_e::kIpV6:
            dumpIpV6Packet(packet_header, ethernet_header);
            break;
        default:
            std::cout << "Unhandled ethertype " << std::hex << ethernet_header.getEtherTypeHbo() << std::dec << std::endl;
    }
}

} // namespace pcap

int main(int argc, char *argv[]) {
    constexpr char kSyntax[] = "dump_pcap_ipv6 PCAP_FILE";

    if (argc != 2) {
        std::cerr << kSyntax << std::endl;
        return 0;
    }

    // XXX - Open the pcap_file_reader.
    pcap::PcapFileReader reader(argv[1]);

    // XXX - loop over the packets, dump each to stdout.
    while (reader.readNextPacket()) {
        dumpPacket(reader.getPcapPacketHeader(),
                   reader.getEthernetHeader());
    }

    std::cout << "Number of packets read: " << reader.getNumPacketsRead() << std::endl;

    return 0;
}
