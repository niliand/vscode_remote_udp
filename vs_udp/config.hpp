
#ifndef _CONFIG_HPP_
#define _CONFIG_HPP_

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <algorithm>

// Trim whitespace from both ends of a string
std::string trim(const std::string& str) {
    const auto strBegin = str.find_first_not_of(" \t");
    if (strBegin == std::string::npos) return "";

    const auto strEnd = str.find_last_not_of(" \t");
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

// Parse config file into a map
std::unordered_map<std::string, std::string> parseConfigFile(const std::string& filename) {
    std::ifstream infile(filename);
    std::unordered_map<std::string, std::string> config;
    std::string line;

    while (std::getline(infile, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        auto delimiterPos = line.find('=');
        if (delimiterPos == std::string::npos) continue;

        std::string key = trim(line.substr(0, delimiterPos));
        std::string value = trim(line.substr(delimiterPos + 1));

        // Remove optional quotes around string values
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        config[key] = value;
    }

    return config;
}

#endif // _CONFIG_HPP_