#include "flow.h"

#include <algorithm>
#include <tuple>

bool Endpoint::operator<(const Endpoint& other) const
{
    return std::tie(ip, port) < std::tie(other.ip, other.port);
}

bool Endpoint::operator==(const Endpoint& other) const
{
    return ip == other.ip && port == other.port;
}

bool FlowKey::operator<(const FlowKey& other) const
{
    return std::tie(protocol, first.ip, first.port, second.ip, second.port) <
           std::tie(other.protocol, other.first.ip, other.first.port, other.second.ip, other.second.port);
}

void TcpStream::insert(uint32_t sequence, const std::vector<uint8_t>& payload)
{
    if(payload.empty()) return;
    constexpr size_t maximumInspectionBytes = 1024U * 1024U;
    constexpr size_t maximumSegments = 4096;
    auto existing = pending.find(sequence);
    if(existing == pending.end())
    {
        if(pending.size() >= maximumSegments) return;
        pending.emplace(sequence, payload);
    }
    else if(existing->second.size() < payload.size())
    {
        existing->second = payload;
    }

    // Rebuild from the earliest observed sequence. This lets a late-arriving
    // earlier segment repair a stream that initially began in the middle.
    data.clear();
    if(pending.empty()) return;
    initialized = true;
    nextSequence = pending.begin()->first;

    for(const auto& segment : pending)
    {
        const int32_t relation = static_cast<int32_t>(segment.first - nextSequence);
        if(relation > 0) break; // A gap remains; wait for the missing segment.
        const size_t overlap = static_cast<size_t>(nextSequence - segment.first);
        if(overlap >= segment.second.size()) continue;
        const size_t appendLength = std::min(segment.second.size() - overlap,
                                             maximumInspectionBytes - data.size());
        data.insert(data.end(), segment.second.begin() + static_cast<std::ptrdiff_t>(overlap),
                    segment.second.begin() + static_cast<std::ptrdiff_t>(overlap + appendLength));
        nextSequence += static_cast<uint32_t>(segment.second.size() - overlap);
        if(data.size() == maximumInspectionBytes) break;
    }
}

Flow& FlowTable::getOrCreate(uint8_t protocol,
                             const Endpoint& source,
                             const Endpoint& destination,
                             bool sourceIsClient)
{
    FlowKey key;
    key.protocol = protocol;
    if(destination < source)
    {
        key.first = destination;
        key.second = source;
    }
    else
    {
        key.first = source;
        key.second = destination;
    }

    auto iterator = flows_.find(key);
    const bool inserted = iterator == flows_.end();
    if(inserted)
    {
        iterator = flows_.emplace(key, Flow{}).first;
    }
    Flow& flow = iterator->second;
    if(inserted)
    {
        flow.key = key;
        flow.client = sourceIsClient ? source : destination;
        flow.server = sourceIsClient ? destination : source;
    }
    return flow;
}

bool FlowTable::sourceIsFirst(const Flow& flow, const Endpoint& source)
{
    return flow.key.first == source;
}
