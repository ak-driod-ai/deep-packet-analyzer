#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct UDPHeader
{
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    uint16_t length = 0;
    size_t payloadOffset = 0;
    size_t payloadLength = 0;
};

bool parseUDP(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t availableLength,
              UDPHeader& header,
              std::string& error);
