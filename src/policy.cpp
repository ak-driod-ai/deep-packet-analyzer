#include "policy.h"

#include <algorithm>
#include <cctype>

PolicyEngine::PolicyEngine(PolicyConfig config)
    : config_(std::move(config))
{
    for(auto& host : config_.blockedHosts) host = normalizeHostname(host);
}

void PolicyEngine::account(const std::string& subscriber, uint64_t bytes)
{
    subscriberBytes_[subscriber] += bytes;
}

std::string PolicyEngine::normalizeHostname(std::string hostname)
{
    while(!hostname.empty() && std::isspace(static_cast<unsigned char>(hostname.front()))) hostname.erase(hostname.begin());
    while(!hostname.empty() && std::isspace(static_cast<unsigned char>(hostname.back()))) hostname.pop_back();
    std::transform(hostname.begin(), hostname.end(), hostname.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    if(!hostname.empty() && hostname.back() == '.') hostname.pop_back();
    if(!hostname.empty() && hostname.front() != '[')
    {
        const size_t colon = hostname.rfind(':');
        if(colon != std::string::npos && hostname.find(':') == colon)
            hostname.erase(colon);
    }
    return hostname;
}

bool PolicyEngine::isBlocked(const std::string& hostname) const
{
    const std::string normalized = normalizeHostname(hostname);
    if(normalized.empty()) return false;
    for(const std::string& blocked : config_.blockedHosts)
    {
        if(blocked.empty()) continue;
        if(normalized == blocked) return true;
        if(normalized.size() > blocked.size() &&
           normalized.compare(normalized.size() - blocked.size(), blocked.size(), blocked) == 0 &&
           normalized[normalized.size() - blocked.size() - 1] == '.')
            return true;
    }
    return false;
}

bool PolicyEngine::isBlockedIP(const std::string& serverIP) const
{
    return std::find(config_.blockedIPs.begin(), config_.blockedIPs.end(), serverIP) !=
           config_.blockedIPs.end();
}

bool PolicyEngine::isBlockedClient(const std::string& subscriber) const
{
    return std::find(config_.blockedClients.begin(), config_.blockedClients.end(), subscriber) !=
           config_.blockedClients.end();
}

PolicyDecision PolicyEngine::evaluate(const std::string& subscriber,
                                      const std::string& hostname,
                                      const std::string& serverIP) const
{
    if(isBlockedClient(subscriber))
        return {PolicyAction::Block, "client IP is blocked by policy", 0};

    if(isBlocked(hostname))
        return {PolicyAction::Block, "TLS SNI/HTTP/DNS hostname matches blocklist", 0};

    if(isBlockedIP(serverIP))
        return {PolicyAction::Block, "destination IP matches blocklist", 0};

    const auto bytes = subscriberBytes_.find(subscriber);
    const auto exactQuota = config_.clientQuotaBytes.find(subscriber);
    if(exactQuota != config_.clientQuotaBytes.end() &&
       bytes != subscriberBytes_.end() &&
       bytes->second > exactQuota->second)
    {
        const auto rate = config_.clientQuotaRateKbps.find(subscriber);
        return {PolicyAction::Throttle,
                "client-specific quota exhausted",
                rate == config_.clientQuotaRateKbps.end() ? config_.exhaustedRateKbps : rate->second};
    }

    const auto exactThrottle = config_.throttledClientsKbps.find(subscriber);
    if(exactThrottle != config_.throttledClientsKbps.end())
        return {PolicyAction::Throttle, "client IP is throttled by policy", exactThrottle->second};

    if(config_.quotaBytes > 0 &&
       bytes != subscriberBytes_.end() &&
       bytes->second > config_.quotaBytes)
    {
        return {PolicyAction::Throttle, "subscriber quota exhausted", config_.exhaustedRateKbps};
    }

    return {};
}

const char* PolicyEngine::actionName(PolicyAction action)
{
    switch(action)
    {
        case PolicyAction::Block: return "BLOCK";
        case PolicyAction::Throttle: return "THROTTLE";
        default: return "ALLOW";
    }
}
