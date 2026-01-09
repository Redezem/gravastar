#include "util.h"

#include <cctype>
#include <iostream>

namespace gravastar {

namespace {

bool g_debug_enabled = false;

} // namespace

std::string Trim(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string ToLower(const std::string &s) {
    std::string out = s;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[i])));
    }
    return out;
}

std::vector<std::string> Split(const std::string &s, char delim) {
    std::vector<std::string> parts;
    std::string cur;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == delim) {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(s[i]);
        }
    }
    parts.push_back(cur);
    return parts;
}

bool StartsWith(const std::string &s, const std::string &prefix) {
    if (prefix.size() > s.size()) {
        return false;
    }
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (s[i] != prefix[i]) {
            return false;
        }
    }
    return true;
}

void SetDebugEnabled(bool enabled) {
    g_debug_enabled = enabled;
}

bool DebugEnabled() {
    return g_debug_enabled;
}

void DebugLog(const std::string &msg) {
    if (!g_debug_enabled) {
        return;
    }
    std::cerr << "[debug] " << msg << "\n";
}

} // namespace gravastar
