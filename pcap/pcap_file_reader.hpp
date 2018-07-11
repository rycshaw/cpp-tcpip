
#pragma once

#include "pcap/packet_headers.hpp"

namespace pcap {

/**
 * @brief class to read from a Pcap file.
 * Typical use:
 * ```
 *    PcapFileReader reader("capture.tcpdump");
 *    const auto *pcap_file_header = reader.getPcapFileHeader();
 *    // Do something with the pcap file header
 *    while (reader.readNextPacket()) {
 *       const auto *pcap_packet_header = reader.getPcapPacketHeader();
 *       const auto *ethernet_header = reader.getEthernetHeader();
 *       switch (ethernet_header->getEtherTypeHbo()) {
 *           case EtherType_e::IpV4:
 *               const IpV4Header_t *ipv4_header = reinterpret_cast<const IpV4Header*>(ethernet_header->getPayloadPtr());
 *               // Do something with the IpV4 header, including access TCP or UDP header from the ip payload.
                 break;
 *           case EtherType_e::IpV6:
 *               const IpV6Header_t *ipv6_header = reinterpret_cast<const IpV6Header*>(ethernet_header->getPayloadPtr());
 *               // Do something with the IpV6 header, including access the extension headers or access TCP or UDP header from the ip payload.
                 break;
 *       } // switch
 *    } // while
 * ```
 */
class PcapFileReader {
public:
    /**
     * @brief Open a pcap file. Automatically reads in the pcap file header, but not the first packet.
     */
    PcapFileReader(const std::string &pcap_filename);

    static constexpr size_t kMaxPacketSize = 0x10000; // 65536

    const PcapFileHeader_t &getPcapFileHeader() const;

    /**
     * @brief Read in the next packet.
     * @return true if next packet was read, else false if EOF.
     */
    bool readNextPacket();

    const PcapPacketHeader_t &getPcapPacketHeader() const;
    const EthernetHeader_t &getEthernetHeader() const;

    size_t getNumPacketsRead() const;

private:
    int _fd;
    size_t _num_packets_read;
    bool _eof;
    PcapFileHeader_t _file_header;
    PcapPacketHeader_t _packet_header;
    uint8_t _packet_data[kMaxPacketSize];
};

} // namespace pcap
