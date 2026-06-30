#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct IPv4Header
{
    uint8_t version = 0;
    uint8_t headerLength = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    uint16_t totalLength = 0;
    uint16_t identification = 0;
    uint16_t fragmentOffset = 0;
    bool moreFragments = false;
    std::string sourceIP;
    std::string destinationIP;
    size_t payloadOffset = 0;
    size_t payloadLength = 0;
};

bool parseIPv4(const std::vector<uint8_t>& packet,
               size_t offset,
               IPv4Header& header,
               std::string& error);
