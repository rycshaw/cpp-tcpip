
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
}

const EthernetHeader_t &PcapFileReader::getEthernetHeader() const
{
    RT_ASSERT(_num_packets_read > 0, "No packets read in yet");
    RT_ASSERT(!_eof, "End of file already encountered");

    return *reinterpret_cast<const EthernetHeader_t*>(_packet_data);
}

} // namespace pcap
