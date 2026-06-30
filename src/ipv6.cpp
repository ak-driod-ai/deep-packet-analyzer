#include "ipv6.h"
#include "packet_view.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace
{
std::string address(const std::vector<uint8_t>& packet, size_t offset)
{
    std::ostringstream text;
    text << std::hex;
    for(size_t group = 0; group < 8; ++group)
    {
        if(group != 0) text << ':';
        const uint16_t value = static_cast<uint16_t>((packet[offset + group * 2] << 8) |
                                                     packet[offset + group * 2 + 1]);
        text << value;
    }
    return text.str();
}
}

bool parseIPv6(const std::vector<uint8_t>& packet,
               size_t offset,
               IPv6Header& header,
               std::string& error)
{
    PacketView view(packet, offset);
    uint8_t first = 0;
    uint16_t declaredPayload = 0;
    uint8_t nextHeader = 0;
    uint8_t hopLimit = 0;
    if(!view.u8(0, first) || !view.be16(4, declaredPayload) ||
       !view.u8(6, nextHeader) || !view.u8(7, hopLimit) || !view.contains(0, 40))
    {
        error = "truncated IPv6 header";
        return false;
    }
    if((first >> 4) != 6)
    {
        error = "invalid IPv6 version";
        return false;
    }

    size_t cursor = 40;
    size_t remaining = std::min<size_t>(declaredPayload, view.size() - 40);
    bool fragmented = false;
    size_t extensionCount = 0;
    while(extensionCount++ < 16)
    {
        size_t extensionLength = 0;
        uint8_t followingHeader = 0;
        if(nextHeader == 0 || nextHeader == 43 || nextHeader == 60)
        {
            uint8_t lengthUnits = 0;
            if(remaining < 8 || !view.u8(cursor, followingHeader) || !view.u8(cursor + 1, lengthUnits))
            {
                error = "truncated IPv6 extension header";
                return false;
            }
            extensionLength = static_cast<size_t>(lengthUnits + 1) * 8;
        }
        else if(nextHeader == 44)
        {
            uint16_t fragmentField = 0;
            if(remaining < 8 || !view.u8(cursor, followingHeader) || !view.be16(cursor + 2, fragmentField))
            {
                error = "truncated IPv6 fragment header";
                return false;
            }
            extensionLength = 8;
            fragmented = (fragmentField & 0xfff9) != 0;
        }
        else if(nextHeader == 51)
        {
            uint8_t lengthUnits = 0;
            if(remaining < 8 || !view.u8(cursor, followingHeader) || !view.u8(cursor + 1, lengthUnits))
            {
                error = "truncated IPv6 authentication header";
                return false;
            }
            extensionLength = static_cast<size_t>(lengthUnits + 2) * 4;
        }
        else
        {
            break;
        }

        if(extensionLength > remaining || !view.contains(cursor, extensionLength))
        {
            error = "invalid IPv6 extension header length";
            return false;
        }
        cursor += extensionLength;
        remaining -= extensionLength;
        nextHeader = followingHeader;
    }
    if(extensionCount > 16)
    {
        error = "too many IPv6 extension headers";
        return false;
    }

    header = {};
    header.nextHeader = nextHeader;
    header.hopLimit = hopLimit;
    header.sourceIP = address(packet, offset + 8);
    header.destinationIP = address(packet, offset + 24);
    header.payloadOffset = offset + cursor;
    header.payloadLength = remaining;
    header.fragmented = fragmented;
    return true;
}
