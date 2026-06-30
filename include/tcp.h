#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct TCPHeader
{
    uint16_t sourcePort = 0;
    uint16_t destinationPort = 0;
    uint32_t sequenceNumber = 0;
    uint32_t acknowledgementNumber = 0;
    uint8_t headerLength = 0;
    bool fin = false;
    bool syn = false;
    bool rst = false;
    bool psh = false;
    bool ack = false;
    bool urg = false;
    size_t payloadOffset = 0;
    size_t payloadLength = 0;
};

bool parseTCP(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t availableLength,
              TCPHeader& header,
              std::string& error);
