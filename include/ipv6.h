#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct IPv6Header
{
    uint8_t nextHeader = 0;
    uint8_t hopLimit = 0;
    std::string sourceIP;
    std::string destinationIP;
    size_t payloadOffset = 0;
    size_t payloadLength = 0;
    bool fragmented = false;
};

bool parseIPv6(const std::vector<uint8_t>& packet,
               size_t offset,
               IPv6Header& header,
               std::string& error);
