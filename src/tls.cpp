#include "tls.h"
#include "packet_view.h"

#include <algorithm>

namespace
{
ParseStatus parseHelloBody(const std::vector<uint8_t>& body,
                           TLSClientHello& hello,
                           std::string& error)
{
    PacketView view(body);
    size_t cursor = 0;
    uint16_t version = 0;
    if(!view.be16(cursor, version) || !view.contains(2, 32))
        return ParseStatus::Malformed;
    cursor = 34;

    uint8_t sessionLength = 0;
    if(!view.u8(cursor, sessionLength)) return ParseStatus::Malformed;
    cursor += 1;
    if(!view.contains(cursor, sessionLength)) return ParseStatus::Malformed;
    cursor += sessionLength;

    uint16_t cipherLength = 0;
    if(!view.be16(cursor, cipherLength) || cipherLength == 0 || (cipherLength % 2) != 0)
        return ParseStatus::Malformed;
    cursor += 2;
    if(!view.contains(cursor, cipherLength)) return ParseStatus::Malformed;
    cursor += cipherLength;

    uint8_t compressionLength = 0;
    if(!view.u8(cursor, compressionLength)) return ParseStatus::Malformed;
    cursor += 1;
    if(!view.contains(cursor, compressionLength)) return ParseStatus::Malformed;
    cursor += compressionLength;

    hello = {};
    hello.legacyVersion = version;
    if(cursor == body.size()) return ParseStatus::Parsed;

    uint16_t extensionsLength = 0;
    if(!view.be16(cursor, extensionsLength)) return ParseStatus::Malformed;
    cursor += 2;
    if(!view.contains(cursor, extensionsLength)) return ParseStatus::Malformed;
    const size_t extensionsEnd = cursor + extensionsLength;

    while(cursor + 4 <= extensionsEnd)
    {
        uint16_t type = 0;
        uint16_t length = 0;
        if(!view.be16(cursor, type) || !view.be16(cursor + 2, length)) return ParseStatus::Malformed;
        cursor += 4;
        if(cursor + length > extensionsEnd) return ParseStatus::Malformed;

        if(type == 0 && length >= 5)
        {
            uint16_t listLength = 0;
            if(!view.be16(cursor, listLength) || listLength + 2 > length)
                return ParseStatus::Malformed;
            size_t nameCursor = cursor + 2;
            const size_t nameEnd = cursor + 2 + listLength;
            while(nameCursor + 3 <= nameEnd)
            {
                uint8_t nameType = 0;
                uint16_t nameLength = 0;
                if(!view.u8(nameCursor, nameType) || !view.be16(nameCursor + 1, nameLength) ||
                   nameCursor + 3 + nameLength > nameEnd)
                    return ParseStatus::Malformed;
                if(nameType == 0 && nameLength > 0)
                {
                    const auto bytes = view.copy(nameCursor + 3, nameLength);
                    if(std::any_of(bytes.begin(), bytes.end(), [](uint8_t c) { return c < 0x21 || c > 0x7e; }))
                        return ParseStatus::Malformed;
                    hello.serverName.assign(bytes.begin(), bytes.end());
                    break;
                }
                nameCursor += 3 + nameLength;
            }
        }
        else if(type == 16 && length >= 3)
        {
            uint16_t listLength = 0;
            if(!view.be16(cursor, listLength) || listLength + 2 > length)
                return ParseStatus::Malformed;
            size_t alpnCursor = cursor + 2;
            const size_t alpnEnd = alpnCursor + listLength;
            while(alpnCursor < alpnEnd)
            {
                uint8_t protocolLength = 0;
                if(!view.u8(alpnCursor, protocolLength) || protocolLength == 0 ||
                   alpnCursor + 1 + protocolLength > alpnEnd)
                    return ParseStatus::Malformed;
                const auto bytes = view.copy(alpnCursor + 1, protocolLength);
                hello.alpnProtocols.emplace_back(bytes.begin(), bytes.end());
                alpnCursor += 1 + protocolLength;
            }
        }
        cursor += length;
    }

    if(cursor != extensionsEnd)
    {
        error = "TLS extension block is misaligned";
        return ParseStatus::Malformed;
    }
    return ParseStatus::Parsed;
}
}

ParseStatus parseTLSClientHello(const std::vector<uint8_t>& stream,
                                TLSClientHello& hello,
                                std::string& error)
{
    hello = {};
    error.clear();
    PacketView view(stream);
    if(stream.size() < 5) return ParseStatus::NeedMoreData;

    std::vector<uint8_t> handshake;
    size_t cursor = 0;
    while(cursor + 5 <= stream.size())
    {
        uint8_t contentType = 0;
        uint16_t recordVersion = 0;
        uint16_t recordLength = 0;
        if(!view.u8(cursor, contentType) || !view.be16(cursor + 1, recordVersion) ||
           !view.be16(cursor + 3, recordLength))
            return ParseStatus::NeedMoreData;

        if(contentType != 22 || (recordVersion >> 8) != 3)
            return handshake.empty() ? ParseStatus::NoMatch : ParseStatus::Malformed;
        if(recordLength > 18432)
        {
            error = "TLS record is too large";
            return ParseStatus::Malformed;
        }
        if(!view.contains(cursor + 5, recordLength)) return ParseStatus::NeedMoreData;
        const auto record = view.copy(cursor + 5, recordLength);
        handshake.insert(handshake.end(), record.begin(), record.end());
        cursor += 5 + recordLength;

        if(handshake.size() >= 4)
        {
            PacketView handshakeView(handshake);
            uint8_t handshakeType = 0;
            uint32_t helloLength = 0;
            handshakeView.u8(0, handshakeType);
            handshakeView.be24(1, helloLength);
            if(handshakeType != 1) return ParseStatus::NoMatch;
            if(helloLength > 1024U * 1024U)
            {
                error = "TLS ClientHello is too large";
                return ParseStatus::Malformed;
            }
            if(handshake.size() >= 4 + helloLength)
            {
                const auto body = handshakeView.copy(4, helloLength);
                return parseHelloBody(body, hello, error);
            }
        }
    }
    return ParseStatus::NeedMoreData;
}
