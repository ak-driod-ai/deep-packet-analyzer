#include "stats.h"

#include <ostream>

void printStatistics(const Statistics& stats, std::ostream& output)
{
    output << "\n========== DPI SUMMARY ==========\n"
           << "Total packets       : " << stats.totalPackets << '\n'
           << "Captured bytes      : " << stats.capturedBytes << '\n'
           << "Malformed packets   : " << stats.malformedPackets << '\n'
           << "Ethernet packets    : " << stats.ethernetPackets << '\n'
           << "VLAN packets        : " << stats.vlanPackets << '\n'
           << "IPv4 packets        : " << stats.ipv4Packets << '\n'
           << "IPv6 packets        : " << stats.ipv6Packets << '\n'
           << "IPv4 fragments      : " << stats.fragmentedIPv4Packets << '\n'
           << "IPv6 fragments      : " << stats.fragmentedIPv6Packets << '\n'
           << "TCP packets         : " << stats.tcpPackets << '\n'
           << "UDP packets         : " << stats.udpPackets << '\n'
           << "DNS queries         : " << stats.dnsQueries << '\n'
           << "HTTP flows          : " << stats.httpFlows << '\n'
           << "TLS flows           : " << stats.tlsFlows << '\n';
}
