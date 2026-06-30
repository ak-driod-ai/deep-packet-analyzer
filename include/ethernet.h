#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct EthernetHeader
{
    std::string destinationMAC;
    std::string sourceMAC;
    uint16_t etherType = 0;
    size_t payloadOffset = 0;
    std::vector<uint16_t> vlanIds;
};

bool parseEthernet(const std::vector<uint8_t>& packet, EthernetHeader& header, std::string& error);
