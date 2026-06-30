#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

enum class PolicyAction
{
    Allow,
    Block,
    Throttle
};

struct PolicyDecision
{
    PolicyAction action = PolicyAction::Allow;
    std::string reason;
    uint32_t rateKbps = 0;
};


struct PolicyConfig
{
    std::vector<std::string> blockedHosts;
    std::vector<std::string> blockedIPs;
    std::vector<std::string> blockedClients;
    std::map<std::string, uint32_t> throttledClientsKbps;
    std::map<std::string, uint64_t> clientQuotaBytes;
    std::map<std::string, uint32_t> clientQuotaRateKbps;
    uint64_t quotaBytes = 0;
    uint32_t exhaustedRateKbps = 128;
};

class PolicyEngine
{
public:
    explicit PolicyEngine(PolicyConfig config = {});

    void account(const std::string& subscriber, uint64_t bytes);
    PolicyDecision evaluate(const std::string& subscriber,
                            const std::string& hostname,
                            const std::string& serverIP) const;

    static std::string normalizeHostname(std::string hostname);
    static const char* actionName(PolicyAction action);

private:
    bool isBlocked(const std::string& hostname) const;
    bool isBlockedIP(const std::string& serverIP) const;
    bool isBlockedClient(const std::string& subscriber) const;

    PolicyConfig config_;
    std::map<std::string, uint64_t> subscriberBytes_;
};
