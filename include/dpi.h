#pragma once

#include "flow.h"
#include "pcap.h"
#include "policy.h"
#include "stats.h"

#include <iosfwd>
#include <cstddef>
#include <set>
#include <string>

class DpiEngine
{
public:
    explicit DpiEngine(PolicyConfig policy = {});

    void process(const Packet& packet);
    void printReport(std::ostream& output, bool verbose = false, size_t topFlowCount = 10) const;

    const Statistics& statistics() const { return stats_; }
    const FlowTable& flows() const { return flows_; }

private:
    void classifyTCP(Flow& flow, TcpStream& stream);
    void applyPolicy(Flow& flow);

    Statistics stats_;
    FlowTable flows_;
    PolicyEngine policy_;
    std::set<FlowKey> countedDnsFlows_;
    std::set<FlowKey> countedHttpFlows_;
    std::set<FlowKey> countedTlsFlows_;
};
