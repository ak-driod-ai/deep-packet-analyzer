#pragma once

#include <cstdint>
#include <iosfwd>

struct Statistics
{
    uint64_t totalPackets = 0;
    uint64_t capturedBytes = 0;
    uint64_t malformedPackets = 0;
    uint64_t ethernetPackets = 0;
    uint64_t vlanPackets = 0;
    uint64_t ipv4Packets = 0;
    uint64_t ipv6Packets = 0;
    uint64_t fragmentedIPv4Packets = 0;
    uint64_t fragmentedIPv6Packets = 0;
    uint64_t tcpPackets = 0;
    uint64_t udpPackets = 0;
    uint64_t dnsQueries = 0;
    uint64_t httpFlows = 0;
    uint64_t tlsFlows = 0;
};

void printStatistics(const Statistics& stats, std::ostream& output);
