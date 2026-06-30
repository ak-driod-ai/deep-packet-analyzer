#pragma once

#include "parse_status.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct DNSQuery
{
    uint16_t transactionID = 0;
    std::string queryName;
    uint16_t queryType = 0;
    uint16_t queryClass = 0;
    bool isResponse = false;
};

bool parseDNS(const std::vector<uint8_t>& packet,
              size_t offset,
              size_t length,
              DNSQuery& query,
              std::string& error);

ParseStatus parseDNSOverTCP(const std::vector<uint8_t>& stream,
                            DNSQuery& query,
                            std::string& error);
