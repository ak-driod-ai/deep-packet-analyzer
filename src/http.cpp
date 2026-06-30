#include "http.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace
{
std::string trim(std::string value)
{
    while(!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while(!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool knownMethod(const std::string& method)
{
    static const std::vector<std::string> methods{
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    };
    return std::find(methods.begin(), methods.end(), method) != methods.end();
}
}

std::string HTTPRequest::url() const
{
    if(host.empty()) return path;
    if(path.rfind("http://", 0) == 0 || path.rfind("https://", 0) == 0) return path;
    return "http://" + host + (path.empty() ? "/" : path);
}

ParseStatus parseHTTP(const std::vector<uint8_t>& stream, HTTPRequest& request)
{
    request = {};
    if(stream.empty()) return ParseStatus::NeedMoreData;

    const std::string text(stream.begin(), stream.end());
    const size_t firstLineEnd = text.find("\r\n");
    if(firstLineEnd == std::string::npos)
        return stream.size() < 8192 ? ParseStatus::NeedMoreData : ParseStatus::NoMatch;

    std::istringstream firstLine(text.substr(0, firstLineEnd));
    if(!(firstLine >> request.method >> request.path >> request.version) || !knownMethod(request.method))
        return ParseStatus::NoMatch;
    if(request.version.rfind("HTTP/", 0) != 0) return ParseStatus::NoMatch;

    const size_t headerEnd = text.find("\r\n\r\n");
    if(headerEnd == std::string::npos)
        return stream.size() < 65536 ? ParseStatus::NeedMoreData : ParseStatus::Malformed;

    size_t cursor = firstLineEnd + 2;
    while(cursor < headerEnd)
    {
        const size_t lineEnd = text.find("\r\n", cursor);
        if(lineEnd == std::string::npos || lineEnd > headerEnd) break;
        const std::string line = text.substr(cursor, lineEnd - cursor);
        const size_t colon = line.find(':');
        if(colon != std::string::npos)
        {
            const std::string name = lower(trim(line.substr(0, colon)));
            const std::string value = trim(line.substr(colon + 1));
            if(name == "host") request.host = value;
            else if(name == "user-agent") request.userAgent = value;
        }
        cursor = lineEnd + 2;
    }

    return ParseStatus::Parsed;
}
