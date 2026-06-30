#include "ipv4.h"
#include "packet_view.h"

#include <algorithm>

bool parseIPv4(const std::vector<uint8_t>& packet,
               size_t offset,
               IPv4Header& header,
               std::string& error)
{
    PacketView view(packet, offset);
    uint8_t first = 0;
    uint16_t totalLength = 0;
    uint16_t identification = 0;
    uint16_t fragment = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    if(!view.u8(0, first) || !view.be16(2, totalLength) ||
       !view.be16(4, identification) || !view.be16(6, fragment) ||
       !view.u8(8, ttl) || !view.u8(9, protocol))
    {
        error = "truncated IPv4 header";
        return false;
    }

    const uint8_t version = static_cast<uint8_t>(first >> 4);
    const uint8_t headerLength = static_cast<uint8_t>((first & 0x0f) * 4);
    if(version != 4 || headerLength < 20)
    {
        error = "invalid IPv4 version or header length";
        return false;
    }
    if(totalLength < headerLength || !view.contains(0, headerLength))
    {
        error = "invalid or truncated IPv4 header";
        return false;
    }

    header = {};
    header.version = version;
    header.headerLength = headerLength;
    header.totalLength = totalLength;
    header.identification = identification;
    header.fragmentOffset = static_cast<uint16_t>(fragment & 0x1fff);
    header.moreFragments = (fragment & 0x2000) != 0;
    header.ttl = ttl;
    header.protocol = protocol;
    header.sourceIP = std::to_string(packet[offset + 12]) + "." +
                      std::to_string(packet[offset + 13]) + "." +
                      std::to_string(packet[offset + 14]) + "." +
                      std::to_string(packet[offset + 15]);
    header.destinationIP = std::to_string(packet[offset + 16]) + "." +
                           std::to_string(packet[offset + 17]) + "." +
                           std::to_string(packet[offset + 18]) + "." +
                           std::to_string(packet[offset + 19]);
    header.payloadOffset = offset + headerLength;
    const size_t declaredPayload = totalLength - headerLength;
    const size_t capturedPayload = packet.size() - header.payloadOffset;
    header.payloadLength = std::min(declaredPayload, capturedPayload);
    return true;
}
