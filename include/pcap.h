#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

struct PcapGlobalHeader
{
    uint16_t versionMajor = 0;
    uint16_t versionMinor = 0;
    uint32_t snapLen = 0;
    uint32_t network = 0;
    bool nanosecondTimestamps = false;
};

struct PcapPacketHeader
{
    uint32_t tsSec = 0;
    uint32_t tsFraction = 0;
    uint32_t capturedLength = 0;
    uint32_t originalLength = 0;
};

struct Packet
{
    PcapPacketHeader header;
    std::vector<uint8_t> data;
};

class PcapReader
{
public:
    explicit PcapReader(const std::string& path);

    bool isOpen() const;
    bool readHeader(std::string& error);
    bool next(Packet& packet, std::string& error);
    const PcapGlobalHeader& header() const { return header_; }

private:
    uint16_t decode16(const uint8_t* bytes) const;
    uint32_t decode32(const uint8_t* bytes) const;

    std::ifstream file_;
    PcapGlobalHeader header_;
    bool littleEndian_ = true;
    bool headerRead_ = false;
    bool modifiedPacketHeader_ = false;
};
