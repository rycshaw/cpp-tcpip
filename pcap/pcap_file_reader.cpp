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

#include "pcap/pcap_file_reader.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

namespace pcap {

PcapFileReader::PcapFileReader(const std::string &pcap_filename)
    : _fd(-1)
    , _num_packets_read(0)
    , _eof(false)
{
    // Open the file
    _fd = open(pcap_filename.c_str(), O_RDONLY);
    RT_ASSERT(_fd != -1, "Failed to open pcap file");

    // Read in the file header
    ssize_t bytes_read = read(_fd, &_file_header, sizeof(_file_header));
    RT_ASSERT(bytes_read > 0, "Failed to read Pcap file header");

    RT_ASSERT(_file_header.magic_number != 0x0d0a0a0d && _file_header.magic_number != 0x0a0d0d0a,
              "pcap-ng files not supported.");

    RT_ASSERT(_file_header.magic_number != 0xd4c3b2a1 && _file_header.magic_number != 0x4d3cb2a1,
              "Endian-ness of pcap file not supported.");

    RT_ASSERT(_file_header.magic_number == 0xa1b2c3d4 || _file_header.magic_number == 0xa1b23c4d,
              "Bad magic_number in file header");
}

const PcapFileHeader_t &PcapFileReader::getPcapFileHeader() const
{
    return _file_header;
}

bool PcapFileReader::readNextPacket()
{
    // Try to read the next pcap packet header into _packet_header
    ssize_t bytes_read = read(_fd, &_packet_header, sizeof(_packet_header));
    if (bytes_read == 0) {
        // 0 bytes read means eof, so set _eof and return false.
        _eof = true;
        return false;
    }
    RT_ASSERT(bytes_read == sizeof(_packet_header), "Failed to fully read pcap packet header");

    RT_ASSERT(_packet_header.incl_len <= kMaxPacketSize, "Too-large (>64kB) packet encountered");

    RT_ASSERT(_packet_header.incl_len == _packet_header.orig_len, "Truncated-capture packet encountered");

    // Try to read the next packet into _packet_data
    bytes_read = read(_fd, &_packet_data, _packet_header.incl_len);
    RT_ASSERT(bytes_read == _packet_header.incl_len, "Failed to fully read pcap packet data");

    ++_num_packets_read;
}

const PcapPacketHeader_t &PcapFileReader::getPcapPacketHeader() const
{
    RT_ASSERT(_num_packets_read > 0, "No packets read in yet");

    return _packet_header;
}

const EthernetHeader_t &PcapFileReader::getEthernetHeader() const
{
    RT_ASSERT(_num_packets_read > 0, "No packets read in yet");
    RT_ASSERT(!_eof, "End of file already encountered");

    return *reinterpret_cast<const EthernetHeader_t*>(_packet_data);
}

size_t PcapFileReader::getNumPacketsRead() const
{
    return _num_packets_read;
}

} // namespace pcap
