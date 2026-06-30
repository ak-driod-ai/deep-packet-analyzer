#include "dns.h"
#include "parse_status.h"

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace
{
std::vector<uint8_t> dnsQueryPayload()
{
    return {
        0x12, 0x34, // transaction ID
        0x01, 0x00, // standard recursive query
        0x00, 0x01, // one question
        0x00, 0x00, // answers
        0x00, 0x00, // authority records
        0x00, 0x00, // additional records
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,
        0x00, 0x01, // A
        0x00, 0x01  // IN
    };
}

std::vector<uint8_t> tcpFramedDNSQuery()
{
    std::vector<uint8_t> message = dnsQueryPayload();
    std::vector<uint8_t> framed{
        static_cast<uint8_t>((message.size() >> 8) & 0xff),
        static_cast<uint8_t>(message.size() & 0xff)
    };
    framed.insert(framed.end(), message.begin(), message.end());
    return framed;
}
}

int main()
{
    std::string error;
    DNSQuery query;

    const std::vector<uint8_t> payload = dnsQueryPayload();
    assert(parseDNS(payload, 0, payload.size(), query, error));
    assert(query.transactionID == 0x1234);
    assert(query.queryName == "www.example.com");
    assert(query.queryType == 1);
    assert(query.queryClass == 1);
    assert(!query.isResponse);

    std::vector<uint8_t> framed = tcpFramedDNSQuery();
    assert(parseDNSOverTCP(framed, query, error) == ParseStatus::Parsed);
    assert(query.queryName == "www.example.com");

    framed.pop_back();
    assert(parseDNSOverTCP(framed, query, error) == ParseStatus::NeedMoreData);

    const std::vector<uint8_t> tooSmallFrame{0x00, 0x0b};
    assert(parseDNSOverTCP(tooSmallFrame, query, error) == ParseStatus::Malformed);

    return 0;
}
