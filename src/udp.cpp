#include "udp.h"
#include "packet_view.h"

#include <algorithm>

bool parseUDP(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t availableLength,
              UDPHeader& header,
              std::string& error)
{
    PacketView view(packet, offset, availableLength);
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    uint16_t length = 0;
    if(!view.be16(0, sourcePort) || !view.be16(2, destinationPort) || !view.be16(4, length))
    {
        error = "truncated UDP header";
        return false;
    }
    if(length < 8)
    {
        error = "invalid UDP length";
        return false;
    }

    header = {};
    header.sourcePort = sourcePort;
    header.destinationPort = destinationPort;
    header.length = length;
    header.payloadOffset = offset + 8;
    header.payloadLength = std::min<size_t>(length - 8, availableLength - 8);
    return true;
}
