#pragma once

#include "policy.h"

#include <string>

bool loadPolicyRules(const std::string& path,
                     PolicyConfig& policy,
                     std::string& error);
