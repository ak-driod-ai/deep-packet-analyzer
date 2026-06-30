#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct Endpoint
{
    std::string ip;
    uint16_t port = 0;

    bool operator<(const Endpoint& other) const;
    bool operator==(const Endpoint& other) const;
};

struct FlowKey
{
    uint8_t protocol = 0;
    Endpoint first;
    Endpoint second;

    bool operator<(const FlowKey& other) const;
};

struct TcpStream
{
    uint32_t nextSequence = 0;
    bool initialized = false;
    std::vector<uint8_t> data;
    std::map<uint32_t, std::vector<uint8_t>> pending;

    void insert(uint32_t sequence, const std::vector<uint8_t>& payload);
};

struct Flow
{
    FlowKey key;
    Endpoint client;
    Endpoint server;
    TcpStream firstToSecond;
    TcpStream secondToFirst;
    uint64_t packetCount = 0;
    uint64_t wireBytes = 0;
    std::string application = "Unknown";
    std::string hostname;
    std::string httpMethod;
    std::string httpPath;
    std::string alpn;
    std::string action = "ALLOW";
    std::string actionReason;
};

class FlowTable
{
public:
    Flow& getOrCreate(uint8_t protocol,
                      const Endpoint& source,
                      const Endpoint& destination,
                      bool sourceIsClient);

    std::map<FlowKey, Flow>& all() { return flows_; }
    const std::map<FlowKey, Flow>& all() const { return flows_; }

    static bool sourceIsFirst(const Flow& flow, const Endpoint& source);

private:
    std::map<FlowKey, Flow> flows_;
};
