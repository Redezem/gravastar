#include "config.h"

#include "util.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace gravastar {

namespace {

bool ParseQuotedString(const std::string &raw, std::string *out) {
    std::string s = Trim(raw);
    if (s.size() < 2 || s[0] != '"' || s[s.size() - 1] != '"') {
        return false;
    }
    *out = s.substr(1, s.size() - 2);
    return true;
}

bool IsValidLogLevel(const std::string &level) {
    if (level == "debug" || level == "info" || level == "warn" || level == "error") {
        return true;
    }
    return false;
}

bool ParseInteger(const std::string &raw, unsigned long *out) {
    std::string s = Trim(raw);
    if (s.empty()) {
        return false;
    }
    char *endptr = 0;
    unsigned long val = std::strtoul(s.c_str(), &endptr, 10);
    if (endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    *out = val;
    return true;
}

bool ParseBool(const std::string &raw, bool *out) {
    if (!out) {
        return false;
    }
    std::string v = ToLower(Trim(raw));
    if (v == "true") {
        *out = true;
        return true;
    }
    if (v == "false") {
        *out = false;
        return true;
    }
    return false;
}

bool ParseStringArray(const std::string &raw, std::vector<std::string> *out) {
    std::string s = Trim(raw);
    if (s.size() < 2 || s[0] != '[' || s[s.size() - 1] != ']') {
        return false;
    }
    std::string inner = Trim(s.substr(1, s.size() - 2));
    if (inner.empty()) {
        return true;
    }
    std::vector<std::string> parts = Split(inner, ',');
    for (size_t i = 0; i < parts.size(); ++i) {
        std::string item;
        if (!ParseQuotedString(parts[i], &item)) {
            return false;
        }
        out->push_back(item);
    }
    return true;
}

bool ExtractQuotedStrings(const std::string &raw, std::vector<std::string> *out) {
    if (!out) {
        return false;
    }
    bool in_quote = false;
    std::string current;
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '"') {
            if (in_quote) {
                out->push_back(current);
                current.clear();
                in_quote = false;
            } else {
                in_quote = true;
            }
            continue;
        }
        if (in_quote) {
            current.push_back(c);
        }
    }
    return true;
}

bool ReadLines(const std::string &path, std::vector<std::string> *lines, std::string *err) {
    std::ifstream in(path.c_str());
    if (!in.is_open()) {
        if (err) {
            *err = "unable to open file: " + path;
        }
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        lines->push_back(line);
    }
    return true;
}

std::string StripComment(const std::string &line) {
    size_t pos = line.find('#');
    if (pos == std::string::npos) {
        return line;
    }
    return line.substr(0, pos);
}

std::string CanonicalName(const std::string &name) {
    std::string lowered = ToLower(name);
    if (!lowered.empty() && lowered[lowered.size() - 1] == '.') {
        lowered.resize(lowered.size() - 1);
    }
    return lowered;
}

} // namespace

bool ConfigLoader::LoadMainConfig(const std::string &path, ServerConfig *out, std::string *err) {
    if (!out) {
        return false;
    }
    out->listen_addr = "0.0.0.0";
    out->listen_port = 53;
    out->cache_size_bytes = 100 * 1024 * 1024;
    out->cache_ttl_sec = 120;
    out->dot_verify = true;
    out->log_level = "debug";
    out->blocklist_file = "blocklist.toml";
    out->local_records_file = "local_records.toml";
    out->upstreams_file = "upstreams.toml";

    std::vector<std::string> lines;
    if (!ReadLines(path, &lines, err)) {
        return false;
    }

    for (size_t i = 0; i < lines.size(); ++i) {
        std::string line = Trim(StripComment(lines[i]));
        if (line.empty()) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = Trim(line.substr(0, eq));
        std::string value = Trim(line.substr(eq + 1));
        if (key == "listen_addr") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid listen_addr";
                return false;
            }
            out->listen_addr = v;
        } else if (key == "listen_port") {
            unsigned long v = 0;
            if (!ParseInteger(value, &v) || v > 65535) {
                if (err) *err = "invalid listen_port";
                return false;
            }
            out->listen_port = static_cast<unsigned short>(v);
        } else if (key == "cache_size_mb") {
            unsigned long v = 0;
            if (!ParseInteger(value, &v)) {
                if (err) *err = "invalid cache_size_mb";
                return false;
            }
            out->cache_size_bytes = static_cast<size_t>(v) * 1024 * 1024;
        } else if (key == "cache_ttl_sec") {
            unsigned long v = 0;
            if (!ParseInteger(value, &v)) {
                if (err) *err = "invalid cache_ttl_sec";
                return false;
            }
            out->cache_ttl_sec = static_cast<unsigned int>(v);
        } else if (key == "dot_verify") {
            bool v = true;
            if (!ParseBool(value, &v)) {
                if (err) *err = "invalid dot_verify";
                return false;
            }
            out->dot_verify = v;
        } else if (key == "log_level") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid log_level";
                return false;
            }
            v = ToLower(v);
            if (!IsValidLogLevel(v)) {
                if (err) *err = "invalid log_level";
                return false;
            }
            out->log_level = v;
        } else if (key == "blocklist_file") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid blocklist_file";
                return false;
            }
            out->blocklist_file = v;
        } else if (key == "local_records_file") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid local_records_file";
                return false;
            }
            out->local_records_file = v;
        } else if (key == "upstreams_file") {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) *err = "invalid upstreams_file";
                return false;
            }
            out->upstreams_file = v;
        }
    }
    return true;
}

bool ConfigLoader::LoadBlocklist(const std::string &path, std::set<std::string> *out, std::string *err) {
    if (!out) {
        return false;
    }
    std::ifstream in(path.c_str());
    if (!in.is_open()) {
        if (err) {
            *err = "unable to open file: " + path;
        }
        return false;
    }
    std::string line;
    bool in_domains = false;
    while (std::getline(in, line)) {
        std::string trimmed = Trim(StripComment(line));
        if (trimmed.empty()) {
            continue;
        }
        if (!in_domains) {
            size_t eq = trimmed.find('=');
            if (eq == std::string::npos) {
                continue;
            }
            std::string key = Trim(trimmed.substr(0, eq));
            if (key != "domains") {
                continue;
            }
            in_domains = true;
            std::string value = Trim(trimmed.substr(eq + 1));
            std::vector<std::string> items;
            ExtractQuotedStrings(value, &items);
            for (size_t j = 0; j < items.size(); ++j) {
                out->insert(CanonicalName(items[j]));
            }
            if (value.find(']') != std::string::npos) {
                in_domains = false;
            }
            continue;
        }
        std::vector<std::string> items;
        ExtractQuotedStrings(trimmed, &items);
        for (size_t j = 0; j < items.size(); ++j) {
            out->insert(CanonicalName(items[j]));
        }
        if (trimmed.find(']') != std::string::npos) {
            in_domains = false;
        }
    }
    return true;
}

bool ConfigLoader::LoadLocalRecords(const std::string &path, std::vector<LocalRecord> *out, std::string *err) {
    if (!out) {
        return false;
    }
    std::vector<std::string> lines;
    if (!ReadLines(path, &lines, err)) {
        return false;
    }
    std::string current_table;
    LocalRecord current;
    bool in_record = false;

    for (size_t i = 0; i < lines.size(); ++i) {
        std::string raw = Trim(StripComment(lines[i]));
        if (raw.empty()) {
            continue;
        }
        if (StartsWith(raw, "[[") && raw.size() > 4 && raw.substr(raw.size() - 2) == "]]" ) {
            if (in_record) {
                if (current.name.empty() || current.type.empty() || current.value.empty()) {
                    if (err) *err = "incomplete local record";
                    return false;
                }
                out->push_back(current);
                current = LocalRecord();
            }
            current_table = Trim(raw.substr(2, raw.size() - 4));
            in_record = (current_table == "record");
            continue;
        }
        size_t eq = raw.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = Trim(raw.substr(0, eq));
        std::string value = Trim(raw.substr(eq + 1));
        if (in_record) {
            std::string v;
            if (!ParseQuotedString(value, &v)) {
                if (err) {
                    std::ostringstream msg;
                    msg << "invalid local record value at line " << (i + 1);
                    *err = msg.str();
                }
                return false;
            }
            if (key == "name") {
                current.name = CanonicalName(v);
            } else if (key == "type") {
                current.type = ToLower(v);
            } else if (key == "value") {
                current.value = v;
            }
        }
    }

    if (in_record) {
        if (current.name.empty() || current.type.empty() || current.value.empty()) {
            if (err) *err = "incomplete local record";
            return false;
        }
        out->push_back(current);
    }
    return true;
}

bool ConfigLoader::LoadUpstreams(const std::string &path,
                                 std::vector<std::string> *udp_out,
                                 std::vector<std::string> *dot_out,
                                 std::string *err) {
    if (!udp_out || !dot_out) {
        return false;
    }
    std::vector<std::string> lines;
    if (!ReadLines(path, &lines, err)) {
        return false;
    }
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string line = Trim(StripComment(lines[i]));
        if (line.empty()) {
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = Trim(line.substr(0, eq));
        std::string value = Trim(line.substr(eq + 1));
        if (key == "udp_servers") {
            while (value.find(']') == std::string::npos && i + 1 < lines.size()) {
                ++i;
                std::string next = Trim(StripComment(lines[i]));
                if (!next.empty()) {
                    value.append(next);
                }
            }
            if (!ParseStringArray(value, udp_out)) {
                if (err) *err = "invalid udp_servers";
                return false;
            }
        } else if (key == "dot_servers") {
            while (value.find(']') == std::string::npos && i + 1 < lines.size()) {
                ++i;
                std::string next = Trim(StripComment(lines[i]));
                if (!next.empty()) {
                    value.append(next);
                }
            }
            if (!ParseStringArray(value, dot_out)) {
                if (err) *err = "invalid dot_servers";
                return false;
            }
        }
    }
    return true;
}

} // namespace gravastar
