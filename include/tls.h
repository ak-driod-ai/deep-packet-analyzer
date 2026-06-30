#pragma once

#include "parse_status.h"

#include <cstdint>
#include <string>
#include <vector>

struct TLSClientHello
{
    uint16_t legacyVersion = 0;
    std::string serverName;
    std::vector<std::string> alpnProtocols;
};

ParseStatus parseTLSClientHello(const std::vector<uint8_t>& stream,
                                TLSClientHello& hello,
                                std::string& error);
