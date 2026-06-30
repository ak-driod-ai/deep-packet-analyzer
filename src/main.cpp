#include "dpi.h"
#include "pcap.h"
#include "policy_loader.h"

#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <string>

namespace
{
void usage(const char* program)
{
    std::cout << "Usage: " << program << " [capture.pcap] [options]\n\n"
              << "Options:\n"
              << "  --policy FILE         Load policy rules from FILE (default: policy.rules if present)\n"
              << "  --no-policy-file      Do not auto-load policy.rules\n"
              << "  --block HOST          Block HOST and its subdomains (repeatable)\n"
              << "  --block-ip ADDRESS    Block an exact destination IPv4/IPv6 address\n"
              << "  --block-client IP     Block all traffic from a client/subscriber IP\n"
              << "  --throttle-client IP RATE_KBPS\n"
              << "                        Slow a client/subscriber IP to RATE_KBPS in the report\n"
              << "  --quota-bytes N       Throttle a client after N accounted wire bytes\n"
              << "  --throttle-kbps N     Report this rate after quota exhaustion (default 128)\n"
              << "  --top N               Show the N largest recognized flows (default 10)\n"
              << "  --verbose             Print every flow for forensic inspection\n"
              << "  --help                Show this help\n\n"
              << "This executable analyzes a PCAP and reports policy decisions. It does not\n"
              << "drop or shape live packets; connect PacketEnforcer to an authorized live adapter.\n";
}

bool fileExists(const std::string& path)
{
    std::ifstream file(path);
    return file.good();
}
}

int main(int argc, char* argv[])
{
    std::string capturePath = "captures/http_get.pcap";
    std::string policyPath = "policy.rules";
    bool captureSet = false;
    bool policyFileEnabled = true;
    bool policyFileExplicit = false;
    bool verbose = false;
    size_t topFlowCount = 10;
    PolicyConfig policy;

    try
    {
        for(int index = 1; index < argc; ++index)
        {
            const std::string argument = argv[index];
            if(argument == "--policy" && index + 1 < argc)
            {
                policyPath = argv[++index];
                policyFileEnabled = true;
                policyFileExplicit = true;
            }
            else if(argument == "--no-policy-file")
            {
                policyFileEnabled = false;
            }
        }

        if(policyFileEnabled && (policyFileExplicit || fileExists(policyPath)))
        {
            std::string policyError;
            if(!loadPolicyRules(policyPath, policy, policyError))
            {
                std::cerr << "Policy error: " << policyError << '\n';
                return 2;
            }
        }

        for(int index = 1; index < argc; ++index)
        {
            const std::string argument = argv[index];
            if(argument == "--help")
            {
                usage(argv[0]);
                return 0;
            }
            if(argument == "--policy" && index + 1 < argc)
            {
                ++index;
            }
            else if(argument == "--no-policy-file")
            {
            }
            else if(argument == "--block" && index + 1 < argc)
            {
                policy.blockedHosts.emplace_back(argv[++index]);
            }
            else if(argument == "--block-ip" && index + 1 < argc)
            {
                policy.blockedIPs.emplace_back(argv[++index]);
            }
            else if(argument == "--block-client" && index + 1 < argc)
            {
                policy.blockedClients.emplace_back(argv[++index]);
            }
            else if(argument == "--throttle-client" && index + 2 < argc)
            {
                const std::string client = argv[++index];
                policy.throttledClientsKbps[client] = static_cast<uint32_t>(std::stoul(argv[++index]));
            }
            else if(argument == "--quota-bytes" && index + 1 < argc)
            {
                policy.quotaBytes = std::stoull(argv[++index]);
            }
            else if(argument == "--throttle-kbps" && index + 1 < argc)
            {
                policy.exhaustedRateKbps = static_cast<uint32_t>(std::stoul(argv[++index]));
            }
            else if(argument == "--top" && index + 1 < argc)
            {
                topFlowCount = static_cast<size_t>(std::stoull(argv[++index]));
            }
            else if(argument == "--verbose")
            {
                verbose = true;
            }
            else if(!argument.empty() && argument[0] != '-' && !captureSet)
            {
                capturePath = argument;
                captureSet = true;
            }
            else
            {
                std::cerr << "Unknown or incomplete option: " << argument << "\n\n";
                usage(argv[0]);
                return 2;
            }
        }
    }
    catch(const std::exception& exception)
    {
        std::cerr << "Invalid numeric option: " << exception.what() << '\n';
        return 2;
    }

    PcapReader reader(capturePath);
    if(!reader.isOpen())
    {
        std::cerr << "Could not open capture: " << capturePath << '\n';
        return 1;
    }

    std::string error;
    if(!reader.readHeader(error))
    {
        std::cerr << "PCAP error: " << error << '\n';
        return 1;
    }

    std::cout << "Analyzing " << capturePath << " (PCAP "
              << reader.header().versionMajor << '.' << reader.header().versionMinor << ")\n";
    if(policyFileEnabled && (policyFileExplicit || fileExists(policyPath)))
        std::cout << "Loaded policy rules from " << policyPath << '\n';

    DpiEngine engine(std::move(policy));
    Packet packet;
    while(reader.next(packet, error)) engine.process(packet);
    if(!error.empty())
    {
        std::cerr << "PCAP error: " << error << '\n';
        return 1;
    }

    engine.printReport(std::cout, verbose, topFlowCount);
    return 0;
}
