#pragma once

#include "flow.h"
#include "policy.h"

// Offline PCAP analysis reports decisions only. A live adapter can implement this
// interface with WinDivert/WFP (Windows) or NFQUEUE/tc (Linux).
class PacketEnforcer
{
public:
    virtual ~PacketEnforcer() = default;
    virtual void apply(const Flow& flow, const PolicyDecision& decision) = 0;
};
