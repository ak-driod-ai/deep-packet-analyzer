#include "policy_loader.h"

#include <cctype>
#include <exception>
#include <fstream>
#include <sstream>
#include <vector>

namespace
{
std::string trim(std::string value)
{
    while(!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while(!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    return value;
}

std::vector<std::string> splitWords(const std::string& line)
{
    std::istringstream stream(line);
    std::vector<std::string> words;
    std::string word;
    while(stream >> word) words.push_back(word);
    return words;
}

bool requireCount(const std::vector<std::string>& words,
                  size_t expected,
                  size_t lineNumber,
                  std::string& error)
{
    if(words.size() == expected) return true;
    error = "policy rule line " + std::to_string(lineNumber) +
            " has wrong number of fields for '" + words.front() + "'";
    return false;
}
}

bool loadPolicyRules(const std::string& path,
                     PolicyConfig& policy,
                     std::string& error)
{
    error.clear();
    std::ifstream file(path);
    if(!file.is_open())
    {
        error = "could not open policy rules file: " + path;
        return false;
    }

    std::string line;
    size_t lineNumber = 0;
    try
    {
        while(std::getline(file, line))
        {
            ++lineNumber;
            const size_t comment = line.find('#');
            if(comment != std::string::npos) line.erase(comment);
            line = trim(line);
            if(line.empty()) continue;

            const std::vector<std::string> words = splitWords(line);
            if(words.empty()) continue;

            const std::string& command = words[0];
            if(command == "block-host")
            {
                if(!requireCount(words, 2, lineNumber, error)) return false;
                policy.blockedHosts.push_back(words[1]);
            }
            else if(command == "block-ip")
            {
                if(!requireCount(words, 2, lineNumber, error)) return false;
                policy.blockedIPs.push_back(words[1]);
            }
            else if(command == "block-client")
            {
                if(!requireCount(words, 2, lineNumber, error)) return false;
                policy.blockedClients.push_back(words[1]);
            }
            else if(command == "throttle-client")
            {
                if(!requireCount(words, 3, lineNumber, error)) return false;
                const uint32_t rateKbps = static_cast<uint32_t>(std::stoul(words[2]));
                if(rateKbps == 0)
                {
                    error = "policy rule line " + std::to_string(lineNumber) +
                            " must use a throttle rate greater than zero";
                    return false;
                }
                policy.throttledClientsKbps[words[1]] = rateKbps;
            }
            else if(command == "quota-client")
            {
                if(!requireCount(words, 4, lineNumber, error)) return false;
                const uint64_t quotaBytes = std::stoull(words[2]);
                const uint32_t rateKbps = static_cast<uint32_t>(std::stoul(words[3]));
                if(quotaBytes == 0 || rateKbps == 0)
                {
                    error = "policy rule line " + std::to_string(lineNumber) +
                            " must use quota bytes and rate greater than zero";
                    return false;
                }
                policy.clientQuotaBytes[words[1]] = quotaBytes;
                policy.clientQuotaRateKbps[words[1]] = rateKbps;
            }
            else if(command == "quota-all")
            {
                if(!requireCount(words, 3, lineNumber, error)) return false;
                policy.quotaBytes = std::stoull(words[1]);
                policy.exhaustedRateKbps = static_cast<uint32_t>(std::stoul(words[2]));
                if(policy.quotaBytes == 0 || policy.exhaustedRateKbps == 0)
                {
                    error = "policy rule line " + std::to_string(lineNumber) +
                            " must use quota bytes and rate greater than zero";
                    return false;
                }
            }
            else
            {
                error = "unknown policy rule '" + command + "' on line " + std::to_string(lineNumber);
                return false;
            }
        }
    }
    catch(const std::exception& exception)
    {
        error = "invalid numeric value on policy rule line " +
                std::to_string(lineNumber) + ": " + exception.what();
        return false;
    }

    return true;
}
