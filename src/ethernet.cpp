#include "ethernet.h"
#include "packet_view.h"

#include <cstdio>

namespace
{
std::string formatMac(const std::vector<uint8_t>& packet, size_t offset)
{
    char text[18]{};
    std::snprintf(text, sizeof(text), "%02X:%02X:%02X:%02X:%02X:%02X",
                  packet[offset], packet[offset + 1], packet[offset + 2],
                  packet[offset + 3], packet[offset + 4], packet[offset + 5]);
    return text;
}

bool isVlan(uint16_t etherType)
{
    return etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100;
}
}

bool parseEthernet(const std::vector<uint8_t>& packet, EthernetHeader& header, std::string& error)
{
    PacketView view(packet);
    uint16_t etherType = 0;
    if(!view.contains(0, 14) || !view.be16(12, etherType))
    {
        error = "truncated Ethernet header";
        return false;
    }

    header = {};
    header.destinationMAC = formatMac(packet, 0);
    header.sourceMAC = formatMac(packet, 6);
    size_t cursor = 14;

    while(isVlan(etherType))
    {
        uint16_t tag = 0;
        if(!view.be16(cursor, tag) || !view.be16(cursor + 2, etherType))
        {
            error = "truncated VLAN tag";
            return false;
        }
        header.vlanIds.push_back(static_cast<uint16_t>(tag & 0x0fff));
        cursor += 4;
        if(header.vlanIds.size() > 4)
        {
            error = "too many nested VLAN tags";
            return false;
        }
    }

    header.etherType = etherType;
    header.payloadOffset = cursor;
    return true;
}
