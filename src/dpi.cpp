#include "dpi.h"

#include "dns.h"
#include "ethernet.h"
#include "http.h"
#include "ipv4.h"
#include "ipv6.h"
#include "tcp.h"
#include "tls.h"
#include "udp.h"

#include <algorithm>
#include <iomanip>
#include <map>
#include <ostream>
#include <sstream>
#include <vector>

namespace
{
bool likelyClient(uint16_t sourcePort, uint16_t destinationPort, bool synWithoutAck)
{
    if(synWithoutAck) return true;
    const auto knownService = [](uint16_t port) {
        return port == 53 || port == 80 || port == 443 || port == 8080 || port == 8443;
    };
    if(knownService(destinationPort) && !knownService(sourcePort)) return true;
    if(knownService(sourcePort) && !knownService(destinationPort)) return false;
    return sourcePort >= destinationPort;
}

std::string join(const std::vector<std::string>& values)
{
    std::string result;
    for(const auto& value : values)
    {
        if(!result.empty()) result += ',';
        result += value;
    }
    return result;
}
}

DpiEngine::DpiEngine(PolicyConfig policy)
    : policy_(std::move(policy))
{
}

void DpiEngine::applyPolicy(Flow& flow)
{
    const PolicyDecision decision = policy_.evaluate(flow.client.ip, flow.hostname, flow.server.ip);
    flow.action = PolicyEngine::actionName(decision.action);
    flow.actionReason = decision.reason;
    if(decision.action == PolicyAction::Throttle)
    {
        flow.actionReason += " (" + std::to_string(decision.rateKbps) + " Kbit/s)";
    }
}

void DpiEngine::classifyTCP(Flow& flow, TcpStream& stream)
{
    if(stream.data.empty()) return;

    if(flow.application == "Unknown" && (flow.client.port == 53 || flow.server.port == 53))
    {
        DNSQuery query;
        std::string error;
        const ParseStatus dnsStatus = parseDNSOverTCP(stream.data, query, error);
        if(dnsStatus == ParseStatus::Parsed)
        {
            flow.application = "DNS";
            if(!query.isResponse)
            {
                flow.hostname = PolicyEngine::normalizeHostname(query.queryName);
                if(countedDnsFlows_.insert(flow.key).second) ++stats_.dnsQueries;
            }
        }
    }

    if(flow.application == "Unknown")
    {
        HTTPRequest request;
        const ParseStatus httpStatus = parseHTTP(stream.data, request);
        if(httpStatus == ParseStatus::Parsed)
        {
            flow.application = "HTTP";
            flow.hostname = PolicyEngine::normalizeHostname(request.host);
            flow.httpMethod = request.method;
            flow.httpPath = request.path;
            if(countedHttpFlows_.insert(flow.key).second) ++stats_.httpFlows;
        }
    }

    if(flow.application == "Unknown")
    {
        TLSClientHello hello;
        std::string error;
        const ParseStatus tlsStatus = parseTLSClientHello(stream.data, hello, error);
        if(tlsStatus == ParseStatus::Parsed)
        {
            flow.application = "TLS";
            flow.hostname = PolicyEngine::normalizeHostname(hello.serverName);
            flow.alpn = join(hello.alpnProtocols);
            if(countedTlsFlows_.insert(flow.key).second) ++stats_.tlsFlows;
        }
    }

    applyPolicy(flow);
}

void DpiEngine::process(const Packet& packet)
{
    ++stats_.totalPackets;
    stats_.capturedBytes += packet.data.size();

    EthernetHeader ethernet;
    std::string error;
    if(!parseEthernet(packet.data, ethernet, error))
    {
        ++stats_.malformedPackets;
        return;
    }
    ++stats_.ethernetPackets;
    if(!ethernet.vlanIds.empty()) ++stats_.vlanPackets;
    uint8_t transportProtocol = 0;
    std::string sourceIP;
    std::string destinationIP;
    size_t transportOffset = 0;
    size_t transportLength = 0;

    if(ethernet.etherType == 0x0800)
    {
        IPv4Header ip;
        if(!parseIPv4(packet.data, ethernet.payloadOffset, ip, error))
        {
            ++stats_.malformedPackets;
            return;
        }
        ++stats_.ipv4Packets;
        if(ip.moreFragments || ip.fragmentOffset != 0)
        {
            ++stats_.fragmentedIPv4Packets;
            return; // IP reassembly is deliberately isolated as a future module.
        }
        transportProtocol = ip.protocol;
        sourceIP = ip.sourceIP;
        destinationIP = ip.destinationIP;
        transportOffset = ip.payloadOffset;
        transportLength = ip.payloadLength;
    }
    else if(ethernet.etherType == 0x86dd)
    {
        IPv6Header ip;
        if(!parseIPv6(packet.data, ethernet.payloadOffset, ip, error))
        {
            ++stats_.malformedPackets;
            return;
        }
        ++stats_.ipv6Packets;
        if(ip.fragmented)
        {
            ++stats_.fragmentedIPv6Packets;
            return;
        }
        transportProtocol = ip.nextHeader;
        sourceIP = ip.sourceIP;
        destinationIP = ip.destinationIP;
        transportOffset = ip.payloadOffset;
        transportLength = ip.payloadLength;
    }
    else
    {
        return;
    }

    const uint64_t wireBytes = packet.header.originalLength != 0
        ? packet.header.originalLength
        : packet.data.size();

    if(transportProtocol == 6)
    {
        TCPHeader tcp;
        if(!parseTCP(packet.data, transportOffset, transportLength, tcp, error))
        {
            ++stats_.malformedPackets;
            return;
        }
        ++stats_.tcpPackets;

        const Endpoint source{sourceIP, tcp.sourcePort};
        const Endpoint destination{destinationIP, tcp.destinationPort};
        const bool sourceClient = likelyClient(tcp.sourcePort, tcp.destinationPort, tcp.syn && !tcp.ack);
        Flow& flow = flows_.getOrCreate(6, source, destination, sourceClient);
        ++flow.packetCount;
        flow.wireBytes += wireBytes;
        policy_.account(flow.client.ip, wireBytes);

        if(tcp.payloadLength > 0)
        {
            const auto begin = packet.data.begin() + static_cast<std::ptrdiff_t>(tcp.payloadOffset);
            std::vector<uint8_t> payload(begin, begin + static_cast<std::ptrdiff_t>(tcp.payloadLength));
            TcpStream& stream = FlowTable::sourceIsFirst(flow, source)
                ? flow.firstToSecond
                : flow.secondToFirst;
            const uint32_t payloadSequence = tcp.sequenceNumber + (tcp.syn ? 1U : 0U);
            stream.insert(payloadSequence, payload);
            if(source == flow.client) classifyTCP(flow, stream);
        }
        applyPolicy(flow);
    }
    else if(transportProtocol == 17)
    {
        UDPHeader udp;
        if(!parseUDP(packet.data, transportOffset, transportLength, udp, error))
        {
            ++stats_.malformedPackets;
            return;
        }
        ++stats_.udpPackets;

        const Endpoint source{sourceIP, udp.sourcePort};
        const Endpoint destination{destinationIP, udp.destinationPort};
        const bool sourceClient = likelyClient(udp.sourcePort, udp.destinationPort, false);
        Flow& flow = flows_.getOrCreate(17, source, destination, sourceClient);
        ++flow.packetCount;
        flow.wireBytes += wireBytes;
        policy_.account(flow.client.ip, wireBytes);

        if((udp.sourcePort == 53 || udp.destinationPort == 53 ||
            udp.sourcePort == 5353 || udp.destinationPort == 5353) && udp.payloadLength > 0)
        {
            DNSQuery query;
            if(parseDNS(packet.data, udp.payloadOffset, udp.payloadLength, query, error))
            {
                flow.application = "DNS";
                if(!query.isResponse)
                {
                    ++stats_.dnsQueries;
                    flow.hostname = PolicyEngine::normalizeHostname(query.queryName);
                }
            }
        }
        else if(udp.sourcePort == 443 || udp.destinationPort == 443)
        {
            flow.application = "QUIC"; // Metadata parsing requires a dedicated QUIC Initial decoder.
        }
        applyPolicy(flow);
    }
}

namespace
{
std::string humanBytes(uint64_t bytes)
{
    static const char* units[] = {"B", "KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while(value >= 1024.0 && unit < 3)
    {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream text;
    if(unit == 0) text << bytes;
    else text << std::fixed << std::setprecision(value >= 10.0 ? 1 : 2) << value;
    text << ' ' << units[unit];
    return text.str();
}

std::string endpointText(const Endpoint& endpoint)
{
    if(endpoint.ip.find(':') != std::string::npos)
        return '[' + endpoint.ip + "]:" + std::to_string(endpoint.port);
    return endpoint.ip + ':' + std::to_string(endpoint.port);
}

struct Aggregate
{
    uint64_t flows = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};

struct PolicyAlertAggregate
{
    std::string action;
    std::string target;
    std::string reason;
    uint64_t flows = 0;
    uint64_t packets = 0;
    uint64_t bytes = 0;
};
}

void DpiEngine::printReport(std::ostream& output, bool verbose, size_t topFlowCount) const
{
    printStatistics(stats_, output);

    std::map<std::string, Aggregate> applications;
    std::map<std::string, Aggregate> webHosts;
    std::map<std::string, PolicyAlertAggregate> policyAlerts;
    std::vector<const Flow*> recognizedFlows;
    uint64_t unknownFlows = 0;

    for(const auto& entry : flows_.all())
    {
        const Flow& flow = entry.second;
        Aggregate& application = applications[flow.application];
        ++application.flows;
        application.packets += flow.packetCount;
        application.bytes += flow.wireBytes;

        if(flow.application == "Unknown") ++unknownFlows;
        else recognizedFlows.push_back(&flow);

        if((flow.application == "HTTP" || flow.application == "TLS") && !flow.hostname.empty())
        {
            Aggregate& host = webHosts[flow.hostname];
            ++host.flows;
            host.packets += flow.packetCount;
            host.bytes += flow.wireBytes;
        }
        if(flow.action != "ALLOW")
        {
            std::string target;
            if(flow.actionReason.find("client") != std::string::npos ||
               flow.actionReason.find("subscriber") != std::string::npos)
            {
                target = "client " + flow.client.ip;
            }
            else
            {
                target = !flow.hostname.empty() ? flow.hostname : endpointText(flow.server);
            }
            const std::string key = flow.action + '\t' + target + '\t' + flow.actionReason;
            PolicyAlertAggregate& alert = policyAlerts[key];
            alert.action = flow.action;
            alert.target = target;
            alert.reason = flow.actionReason;
            ++alert.flows;
            alert.packets += flow.packetCount;
            alert.bytes += flow.wireBytes;
        }
    }

    output << "\n========== APPLICATION SUMMARY ==========\n"
           << std::left << std::setw(14) << "Application"
           << std::right << std::setw(9) << "Flows"
           << std::setw(12) << "Packets"
           << std::setw(14) << "Traffic" << '\n';
    for(const auto& item : applications)
    {
        output << std::left << std::setw(14) << item.first
               << std::right << std::setw(9) << item.second.flows
               << std::setw(12) << item.second.packets
               << std::setw(14) << humanBytes(item.second.bytes) << '\n';
    }
    output << "\nTotal flows: " << flows_.all().size()
           << " | Recognized: " << (flows_.all().size() - unknownFlows)
           << " | Unknown: " << unknownFlows << '\n';

    output << "\n========== POLICY ALERTS ==========\n";
    if(policyAlerts.empty()) output << "None\n";
    else
    {
        for(const auto& entry : policyAlerts)
        {
            const PolicyAlertAggregate& alert = entry.second;
            output << alert.action << "  " << alert.target;
            if(!alert.reason.empty()) output << " - " << alert.reason;
            output << " | " << alert.flows << " flow(s), "
                   << alert.packets << " packet(s), "
                   << humanBytes(alert.bytes) << '\n';
        }
    }

    output << "\n========== WEB HOSTS (HTTP HOST / TLS SNI) ==========\n";
    if(webHosts.empty()) output << "No readable HTTP Host or TLS SNI found.\n";
    else
    {
        std::vector<std::pair<std::string, Aggregate>> hosts(webHosts.begin(), webHosts.end());
        std::sort(hosts.begin(), hosts.end(), [](const auto& left, const auto& right) {
            return left.second.bytes > right.second.bytes;
        });
        const size_t hostLimit = std::min<size_t>(hosts.size(), 20);
        for(size_t index = 0; index < hostLimit; ++index)
        {
            output << std::setw(2) << (index + 1) << ". " << std::left << std::setw(42)
                   << hosts[index].first << std::right
                   << std::setw(5) << hosts[index].second.flows << " flow(s)  "
                   << std::setw(10) << humanBytes(hosts[index].second.bytes) << '\n';
        }
        if(hosts.size() > hostLimit)
            output << "... " << (hosts.size() - hostLimit) << " more host(s); use --verbose for all flow details.\n";
    }

    std::sort(recognizedFlows.begin(), recognizedFlows.end(), [](const Flow* left, const Flow* right) {
        return left->wireBytes > right->wireBytes;
    });
    const size_t flowLimit = std::min(topFlowCount, recognizedFlows.size());
    output << "\n========== TOP " << flowLimit << " RECOGNIZED FLOWS ==========\n";
    if(flowLimit == 0) output << "None\n";
    for(size_t index = 0; index < flowLimit; ++index)
    {
        const Flow& flow = *recognizedFlows[index];
        output << (index + 1) << ". " << flow.application << ' '
               << (flow.key.protocol == 6 ? "TCP" : "UDP") << " -> "
               << endpointText(flow.server) << " | " << flow.packetCount << " packets | "
               << humanBytes(flow.wireBytes) << " | " << flow.action << '\n';
        if(!flow.hostname.empty()) output << "   Host: " << flow.hostname << '\n';
    }

    if(!verbose)
    {
        output << "\nUse --verbose to print every flow. Use --top N to change the top-flow count.\n";
        return;
    }

    output << "\n========== FULL FLOW DETAILS ==========\n";
    size_t number = 0;
    for(const auto& entry : flows_.all())
    {
        const Flow& flow = entry.second;
        output << "\nFlow " << ++number << " [" << (flow.key.protocol == 6 ? "TCP" : "UDP") << "]\n"
               << "  Client       : " << endpointText(flow.client) << '\n'
               << "  Server       : " << endpointText(flow.server) << '\n'
               << "  Packets/bytes: " << flow.packetCount << " / " << flow.wireBytes << '\n'
               << "  Application  : " << flow.application << '\n';
        if(!flow.hostname.empty()) output << "  Hostname     : " << flow.hostname << '\n';
        if(!flow.httpMethod.empty()) output << "  HTTP request : " << flow.httpMethod << ' ' << flow.httpPath << '\n';
        if(!flow.alpn.empty()) output << "  ALPN         : " << flow.alpn << '\n';
        output << "  Policy       : " << flow.action;
        if(!flow.actionReason.empty()) output << " - " << flow.actionReason;
        output << '\n';
    }
}
