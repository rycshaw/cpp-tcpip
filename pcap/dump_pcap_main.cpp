/*
 * This source code is distributed under the MIT License.
 *
 * Copyright 2018 Ray Chow (rycshaw@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <iostream>
#include <sstream>

#include "pcap/hexdump.hpp"
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
    std::cout << hexHeader() << printableHeader() << std::endl
              << binaryToString(reinterpret_cast<const uint8_t *>(ip_header), ip_header->getTotalLengthBytes());
}

void dumpIpV6Packet(const pcap::PcapPacketHeader_t &packet_header,
                    const pcap::EthernetHeader_t &ethernet_header)
{
    RT_ASSERT(pcap::EtherType_e(ethernet_header.getEtherTypeHbo()) == EtherType_e::kIpV6, "Expected ethertype == ipv6");
    const IpV6Header_t *ip_header =
        reinterpret_cast<const IpV6Header_t *>(ethernet_header.getPayloadPtr());
    std::cout << "IpV6: next_header: " << static_cast<int>(ip_header->next_header)
              << ", IpPayloadLengthBytes: " << ip_header->getPayloadLengthBytesHbo() << std::endl;
    std::cout << hexHeader() << printableHeader() << std::endl
              << binaryToString(reinterpret_cast<const uint8_t *>(ip_header), ip_header->getTotalLengthBytes());
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

// You can get sample pcap files from http://packetlife.net/captures/protocol/ipv6/
// Note that pcap-ng files are currently not supported.

int main(int argc, char *argv[]) {
    constexpr char kSyntax[] = "dump_pcap_ipv6 PCAP_FILE";

    if (argc != 2) {
        std::cerr << kSyntax << std::endl;
        return 0;
    }

    // Open the pcap_file_reader.
    pcap::PcapFileReader reader(argv[1]);

    // loop over the packets, dump each to stdout.
    while (reader.readNextPacket()) {
        dumpPacket(reader.getPcapPacketHeader(),
                   reader.getEthernetHeader());
    }

    std::cout << "Number of packets read: " << reader.getNumPacketsRead() << std::endl;

    return 0;
}
