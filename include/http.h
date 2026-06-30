#pragma once

#include "parse_status.h"

#include <string>
#include <vector>

struct HTTPRequest
{
    std::string method;
    std::string path;
    std::string version;
    std::string host;
    std::string userAgent;

    std::string url() const;
};

ParseStatus parseHTTP(const std::vector<uint8_t>& stream, HTTPRequest& request);
