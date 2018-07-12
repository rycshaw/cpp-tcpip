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
