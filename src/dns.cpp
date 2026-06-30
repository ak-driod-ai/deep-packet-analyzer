#include "dns.h"
#include "packet_view.h"

namespace
{
bool readName(const std::vector<uint8_t>& packet,
              size_t base,
              size_t length,
              size_t& position,
              std::string& name)
{
    size_t cursor = position;
    size_t resume = position;
    bool jumped = false;
    size_t steps = 0;
    name.clear();

    while(steps++ < 128)
    {
        if(cursor >= length) return false;
        const uint8_t labelLength = packet[base + cursor];
        if((labelLength & 0xc0) == 0xc0)
        {
            if(cursor + 1 >= length) return false;
            const uint16_t pointer = static_cast<uint16_t>(((labelLength & 0x3f) << 8) |
                                                           packet[base + cursor + 1]);
            if(pointer >= length) return false;
            if(!jumped) resume = cursor + 2;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if((labelLength & 0xc0) != 0) return false;
        if(labelLength == 0)
        {
            position = jumped ? resume : cursor + 1;
            return !name.empty();
        }
        if(labelLength > 63 || cursor + 1 + labelLength > length) return false;
        if(!name.empty()) name.push_back('.');
        for(size_t index = 0; index < labelLength; ++index)
        {
            const uint8_t character = packet[base + cursor + 1 + index];
            if(character < 0x21 || character > 0x7e) return false;
            name.push_back(static_cast<char>(character));
        }
        cursor += 1 + labelLength;
        if(!jumped) resume = cursor;
        if(name.size() > 253) return false;
    }
    return false;
}
}

bool parseDNS(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t length,
              DNSQuery& query,
              std::string& error)
{
    PacketView view(packet, offset, length);
    uint16_t transaction = 0;
    uint16_t flags = 0;
    uint16_t questionCount = 0;
    if(!view.be16(0, transaction) || !view.be16(2, flags) || !view.be16(4, questionCount))
    {
        error = "truncated DNS header";
        return false;
    }
    if(questionCount == 0)
    {
        error = "DNS message has no question";
        return false;
    }

    size_t position = 12;
    std::string name;
    if(!readName(packet, offset, length, position, name))
    {
        error = "invalid DNS question name";
        return false;
    }
    uint16_t type = 0;
    uint16_t queryClass = 0;
    if(!view.be16(position, type) || !view.be16(position + 2, queryClass))
    {
        error = "truncated DNS question";
        return false;
    }

    query = {};
    query.transactionID = transaction;
    query.queryName = name;
    query.queryType = type;
    query.queryClass = queryClass;
    query.isResponse = (flags & 0x8000) != 0;
    return true;
}

ParseStatus parseDNSOverTCP(const std::vector<uint8_t>& stream,
                            DNSQuery& query,
                            std::string& error)
{
    query = {};
    error.clear();

    PacketView view(stream);
    uint16_t messageLength = 0;
    if(!view.be16(0, messageLength)) return ParseStatus::NeedMoreData;
    if(messageLength < 12)
    {
        error = "invalid DNS-over-TCP message length";
        return ParseStatus::Malformed;
    }
    if(messageLength > 4096)
    {
        error = "DNS-over-TCP message is too large for inspection";
        return ParseStatus::Malformed;
    }
    if(!view.contains(2, messageLength)) return ParseStatus::NeedMoreData;

    if(!parseDNS(stream, 2, messageLength, query, error))
        return ParseStatus::Malformed;
    return ParseStatus::Parsed;
}
