#include "tcp.h"
#include "packet_view.h"

bool parseTCP(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t availableLength,
              TCPHeader& header,
              std::string& error)
{
    PacketView view(packet, offset, availableLength);
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    uint32_t sequence = 0;
    uint32_t acknowledgement = 0;
    uint8_t offsetByte = 0;
    uint8_t flags = 0;
    if(!view.be16(0, sourcePort) || !view.be16(2, destinationPort) ||
       !view.be32(4, sequence) || !view.be32(8, acknowledgement) ||
       !view.u8(12, offsetByte) || !view.u8(13, flags))
    {
        error = "truncated TCP header";
        return false;
    }

    const uint8_t headerLength = static_cast<uint8_t>((offsetByte >> 4) * 4);
    if(headerLength < 20 || !view.contains(0, headerLength))
    {
        error = "invalid TCP header length";
        return false;
    }

    header = {};
    header.sourcePort = sourcePort;
    header.destinationPort = destinationPort;
    header.sequenceNumber = sequence;
    header.acknowledgementNumber = acknowledgement;
    header.headerLength = headerLength;
    header.fin = (flags & 0x01) != 0;
    header.syn = (flags & 0x02) != 0;
    header.rst = (flags & 0x04) != 0;
    header.psh = (flags & 0x08) != 0;
    header.ack = (flags & 0x10) != 0;
    header.urg = (flags & 0x20) != 0;
    header.payloadOffset = offset + headerLength;
    header.payloadLength = availableLength - headerLength;
    return true;
}
