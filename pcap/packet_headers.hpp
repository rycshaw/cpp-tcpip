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

// Headers for reading ethernet, ip(v4/v6), udp, tcp headers from pcap files.

#pragma once

#include <arpa/inet.h>
#include <cstdint>

#include "util/throw_assert.hpp"

namespace pcap {

// Remove padding of structs in memory.
#pragma pack(push)
#pragma pack(1) // set alignment to 1 byte boundary

// -- PCAP file and packet headers:

struct PcapFileHeader_t {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;       // GMT to local correction
    uint32_t sigfigs;        // accuracy of timestamps
    uint32_t snaplen;        // max length of captured packets, in octets
    uint32_t network;        // data link type
};

struct PcapPacketHeader_t {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;       // number of octets of packet saved in file
    uint32_t orig_len;       // actual length of packet on the wire
};


// -- Ethernet and IP/UDP/TCP headers:


static constexpr size_t kMacAddressLength = 6;
enum class EtherType_e : uint16_t {
    kIpV4 = 0x0800,
    kVlan1Prefix = 0x8100,
    kVlan2Prefix = 0x88a8,
    kIpV6 = 0x86dd
};

struct EthernetHeader_t {
    uint8_t mac_destination[kMacAddressLength];
    uint8_t mac_source[kMacAddressLength];
    uint16_t ethertype;

    const uint16_t getEtherTypeHbo() const {
        // Handle vlan2 + possible vlan1
        if (EtherType_e(ntohs(ethertype)) == EtherType_e::kVlan2Prefix) {
            // There should be a nested 2-byte vlan1.
            RT_ASSERT(EtherType_e(ntohs(*(&ethertype + 1))) == EtherType_e::kVlan1Prefix,
                      "Unexpected value for nested Vlan1 tag");
            return ntohs(*(&ethertype + 2));
        }
        // Handle vlan1
        if (EtherType_e(ntohs(ethertype)) == EtherType_e::kVlan1Prefix) {
            return ntohs(*(&ethertype + 1));
        }
        // Handle no vlan
        return ntohs(ethertype);
    }

    // Return pointer to start of IPv4 or IPV6 header.
    const uint8_t *getPayloadPtr() const {
        switch (EtherType_e(getEtherTypeHbo())) {
            case EtherType_e::kVlan2Prefix: // Handle vlan2 + possible vlan1
                return reinterpret_cast<const uint8_t*>(&ethertype) + sizeof(ethertype) * 4;
            case EtherType_e::kVlan1Prefix: // Handle vlan1
                return reinterpret_cast<const uint8_t*>(&ethertype) + sizeof(ethertype) * 2;
            default: // Handle no vlan
                return reinterpret_cast<const uint8_t*>(&ethertype) + sizeof(ethertype);
        }
    }
};

struct IpV4Header_t {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_ip_address;
    uint32_t destination_ip_address;

    uint16_t getTotalLength() const {
        return ntohs(total_length);
    }
//    uint8_t getProtocol() const {
//        return protocol;
//    }
    uint16_t getHeaderChecksumHbo() const {
        return ntohs(header_checksum);
    }
    uint32_t getSourceIpAddressHbo() const {
        return ntohl(source_ip_address);
    }
    uint32_t getDestinationIpAddressHbo() const {
        return ntohl(destination_ip_address);
    }

    size_t getInternetHeaderLengthBytes() const {
        return (version_ihl & 0xf) * 4;
    }

    // Size of IP headers + payload.
    size_t getTotalLengthBytes() const {
        return ntohs(total_length);
    }

    // Return pointer to start of TCP or UDP header.
    const uint8_t *getPayloadPtr() const {
        return reinterpret_cast<const uint8_t*>(&version_ihl) + getInternetHeaderLengthBytes();
    }

    size_t getPayloadLengthBytesHbo() const {
        return getTotalLengthBytes() - getInternetHeaderLengthBytes();
    }

    // TODO: compute pseudo header checksum differently for ipv4 vs ipv6.
};

struct UdpHeader_t {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;

    uint16_t getSourcePortHbo() const {
        return htons(source_port);
    }
    uint16_t getDestinationPortHbo() const {
        return htons(destination_port);
    }
    // Length of UDP header + UDP data in bytes
    uint16_t getLengthBytesHbo() const {
        return htons(length);
    }
    uint16_t getChecksumHbo() const {
        return htons(checksum);
    }

    const uint8_t *getPayloadPtr() const {
        return reinterpret_cast<const uint8_t*>(&source_port) + sizeof(UdpHeader_t);
    }

    // TODO: compute pseudo header checksum differently for ipv4 vs ipv6.
};

struct TcpHeader_t {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgement_number;
    uint8_t data_offset_reserved_flags;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;

    uint16_t getSourcePortHbo() const {
        return htons(source_port);
    }
    uint16_t getDestinationPortHbo() const {
        return htons(destination_port);
    }
    // Length of TCP header in bytes
    uint16_t getHeaderLengthBytesHbo() const {
        return (data_offset_reserved_flags >> 12) * 4;
    }
    uint16_t getChecksumHbo() const {
        return htons(checksum);
    }

    const uint8_t *getPayloadPtr() const {
        return reinterpret_cast<const uint8_t*>(&source_port) + getHeaderLengthBytesHbo();
    }

    // TODO: compute pseudo header checksum differently for ipv4 vs ipv6.
};

struct IpV6ExtensionHeader_t {
    uint8_t next_header;
    uint8_t header_extension_length;

    enum class HeaderType_e : uint8_t {
        kIpV4Reserved0 = 0,
        kIpV6HopByHop = 0,
        kIpV4Icmp = 1,
        kIpV4Igmp = 2,
        kIpV4 = 4,
        kIpStreamProtocol = 5,
        kTcp = 6,
        kEgp = 8,
        kIgp = 9,
        kUdp = 17,
        kIpV6 = 41,
        kIpV6RoutingHeader = 43,
        kIpV6FragmentationHeader = 44,
        kIdrp = 45,
        kRsvp = 46,
        kGre = 47,
        kIpV6EncapsulatingSecurityPayloadHeader = 50,
        kIpV6AuthenticationHeader = 51,
        kIpV6Icmp = 58,
        kIpV6NoNextHeader = 59,
        kIpV6DestinationOoptionsHeader = 60,
        kEigrp = 88,
        kOspf = 89,
        kPim = 103,
        kIpPayloadCompressionProtocol = 108,
        kL2tp = 115,
        kSctp = 132,
        kIpV6MobilityHeader = 135,
        kShim6 = 140,
        kReserved255 = 255
    };

    // Number of bytes for this Header extension in bytes, INCLUDING the first 8 bytes.
    uint16_t getHeaderExtensionLengthHbo() const {
        return (1 + header_extension_length) * 8;
    }
};

struct IpV6Header_t {
    static constexpr size_t kIpV6AddressNumBytes = 16;

    uint32_t version_traffic_class_flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_address[kIpV6AddressNumBytes];
    uint8_t destination_address[kIpV6AddressNumBytes];

    uint8_t getVersion() const {
        return ntohl(version_traffic_class_flow_label) >> 28;
    }
    uint8_t getDifferentiatedServices() const {
        return (ntohl(version_traffic_class_flow_label) >> 20) & 0xfc;
    }
    uint8_t getExplicitCongestionNotification() const {
        return (ntohl(version_traffic_class_flow_label) >> 20) & 0x3;
    }
    uint32_t getFlowLabelHbo() const {
        return (ntohl(version_traffic_class_flow_label) >> 20) & 0xfffff;
    }
    // Size of the payload in bytes, including any extension headers.
    uint16_t getPayloadLengthBytesHbo() const {
        return ntohs(payload_length);
    }

    // XXX - TODO: support Jumbogram option

    /**
     * @brief Re-entrant function used to determine the length of any one extension header.
     * @param next_header - octet identifying this extension header (usually from the ipv6 base
     *     header or preceding extension_header)
     * @param extension_header_start - start of the extension header in question.
     * @return number of bytes of this extension header. Magic value 0 implies no following headers.
     */
    size_t getExtensionHeaderLengthBytes(uint8_t next_header,
                                         const uint8_t *extension_header_start) const
    {
        switch (IpV6ExtensionHeader_t::HeaderType_e(next_header)) {
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6HopByHop:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6FragmentationHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6EncapsulatingSecurityPayloadHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6AuthenticationHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6Icmp:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6DestinationOoptionsHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6MobilityHeader:
                // The second byte of any extension header should be the Header Extension Length.
                return 8 * *(extension_header_start + 1);

            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6NoNextHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV4Icmp:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV4Igmp:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV4:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpStreamProtocol:
            case IpV6ExtensionHeader_t::HeaderType_e::kTcp:
            case IpV6ExtensionHeader_t::HeaderType_e::kEgp:
            case IpV6ExtensionHeader_t::HeaderType_e::kIgp:
            case IpV6ExtensionHeader_t::HeaderType_e::kUdp:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpV6RoutingHeader:
            case IpV6ExtensionHeader_t::HeaderType_e::kIdrp:
            case IpV6ExtensionHeader_t::HeaderType_e::kRsvp:
            case IpV6ExtensionHeader_t::HeaderType_e::kGre:
            case IpV6ExtensionHeader_t::HeaderType_e::kEigrp:
            case IpV6ExtensionHeader_t::HeaderType_e::kOspf:
            case IpV6ExtensionHeader_t::HeaderType_e::kPim:
            case IpV6ExtensionHeader_t::HeaderType_e::kIpPayloadCompressionProtocol:
            case IpV6ExtensionHeader_t::HeaderType_e::kL2tp:
            case IpV6ExtensionHeader_t::HeaderType_e::kSctp:
            case IpV6ExtensionHeader_t::HeaderType_e::kShim6:
                // No more headers.
                return 0;

//            case IpV6ExtensionHeader_t::HeaderType_e::kIpV4Reserved0:
            case IpV6ExtensionHeader_t::HeaderType_e::kReserved255:
            default:
                RT_THROW("Unhandled ExtensionHeader type");
        }
    }

    // Return the total length of the IpV6 base + extension headers, used to determine
    // where the actual payload (eg the start of the UDP or TCP header) begins.
    size_t getInternetHeaderLengthBytes() const {

        // XXX - iterate over the extension headers
        uint16_t total_header_length = sizeof(IpV6Header_t);
        const uint8_t *extension_header_start = reinterpret_cast<const uint8_t*>(&version_traffic_class_flow_label) + sizeof(IpV6Header_t);
        uint8_t next_header = next_header;
        uint16_t extension_header_length = getExtensionHeaderLengthBytes(next_header, extension_header_start);
        while (extension_header_length > 0) {
            // Add the size of the current extension header.
            total_header_length += extension_header_length;
            // Move on to the next extension header.
            next_header = *(extension_header_start + 1);
            extension_header_start += extension_header_length;
            extension_header_length = getExtensionHeaderLengthBytes(next_header, extension_header_start);
        }

        return total_header_length;
    }

    // Size of IP headers + payload.
    size_t getTotalLengthBytes() const {
        return static_cast<size_t>(ntohs(payload_length)) + sizeof(IpV6Header_t);
    }

    // Return pointer to start of TCP or UDP header.
    const uint8_t *getPayloadPtr() const {
        return reinterpret_cast<const uint8_t*>(&version_traffic_class_flow_label) + getInternetHeaderLengthBytes();
    }

    size_t getPayloadLengthBytes() const {
        return getTotalLengthBytes() - getInternetHeaderLengthBytes();
    }

};

#pragma pack(pop)

} // namespace pcap
