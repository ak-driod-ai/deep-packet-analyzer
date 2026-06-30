#include "pcap.h"

#include <array>
#include <cstring>

PcapReader::PcapReader(const std::string& path)
    : file_(path, std::ios::binary)
{
}

bool PcapReader::isOpen() const
{
    return file_.is_open();
}

uint16_t PcapReader::decode16(const uint8_t* bytes) const
{
    if(littleEndian_)
        return static_cast<uint16_t>(bytes[0] | (static_cast<uint16_t>(bytes[1]) << 8));
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}

uint32_t PcapReader::decode32(const uint8_t* bytes) const
{
    if(littleEndian_)
    {
        return static_cast<uint32_t>(bytes[0]) |
              (static_cast<uint32_t>(bytes[1]) << 8) |
              (static_cast<uint32_t>(bytes[2]) << 16) |
              (static_cast<uint32_t>(bytes[3]) << 24);
    }
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
            static_cast<uint32_t>(bytes[3]);
}

bool PcapReader::readHeader(std::string& error)
{
    std::array<uint8_t, 24> bytes{};
    if(!file_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
    {
        error = "file is too short for a PCAP global header";
        return false;
    }

    const std::array<uint8_t, 4> magic{bytes[0], bytes[1], bytes[2], bytes[3]};
    if(magic == std::array<uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1})
    {
        littleEndian_ = true;
        header_.nanosecondTimestamps = false;
    }
    else if(magic == std::array<uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4})
    {
        littleEndian_ = false;
        header_.nanosecondTimestamps = false;
    }
    else if(magic == std::array<uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1})
    {
        littleEndian_ = true;
        header_.nanosecondTimestamps = true;
    }
    else if(magic == std::array<uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d})
    {
        littleEndian_ = false;
        header_.nanosecondTimestamps = true;
    }
    else if(magic == std::array<uint8_t, 4>{0x34, 0xcd, 0xb2, 0xa1})
    {
        littleEndian_ = true;
        modifiedPacketHeader_ = true;
        header_.nanosecondTimestamps = false;
    }
    else if(magic == std::array<uint8_t, 4>{0xa1, 0xb2, 0xcd, 0x34})
    {
        littleEndian_ = false;
        modifiedPacketHeader_ = true;
        header_.nanosecondTimestamps = false;
    }
    else
    {
        error = "unsupported capture format (classic or modified PCAP required)";
        return false;
    }

    header_.versionMajor = decode16(bytes.data() + 4);
    header_.versionMinor = decode16(bytes.data() + 6);
    header_.snapLen = decode32(bytes.data() + 16);
    header_.network = decode32(bytes.data() + 20);
    if(header_.network != 1)
    {
        error = "unsupported PCAP link type; Ethernet (DLT_EN10MB) is required";
        return false;
    }
    if(header_.snapLen == 0 || header_.snapLen > 64U * 1024U * 1024U)
    {
        error = "invalid PCAP snapshot length";
        return false;
    }

    headerRead_ = true;
    return true;
}

bool PcapReader::next(Packet& packet, std::string& error)
{
    error.clear();
    if(!headerRead_)
    {
        error = "PCAP global header has not been read";
        return false;
    }

    std::array<uint8_t, 24> bytes{};
    const size_t packetHeaderLength = modifiedPacketHeader_ ? 24 : 16;
    file_.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(packetHeaderLength));
    if(file_.gcount() == 0 && file_.eof()) return false;
    if(file_.gcount() != static_cast<std::streamsize>(packetHeaderLength))
    {
        error = "truncated PCAP packet header";
        return false;
    }

    packet.header.tsSec = decode32(bytes.data());
    packet.header.tsFraction = decode32(bytes.data() + 4);
    packet.header.capturedLength = decode32(bytes.data() + 8);
    packet.header.originalLength = decode32(bytes.data() + 12);

    if(packet.header.capturedLength > header_.snapLen ||
       packet.header.capturedLength > 64U * 1024U * 1024U)
    {
        error = "invalid captured packet length";
        return false;
    }

    packet.data.resize(packet.header.capturedLength);
    if(!file_.read(reinterpret_cast<char*>(packet.data.data()),
                   static_cast<std::streamsize>(packet.data.size())))
    {
        error = "truncated PCAP packet data";
        return false;
    }
    return true;
}
