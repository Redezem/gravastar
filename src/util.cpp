#include "util.h"

#include "controller_logger.h"

#include <cctype>
#include <iostream>

namespace gravastar {

void LogInternal(LogLevel level, const std::string &msg);

namespace {

bool g_debug_enabled = false;
LogLevel g_log_level = LOG_DEBUG;
ControllerLogger *g_controller_logger = NULL;

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
    if (enabled) {
        g_log_level = LOG_DEBUG;
    }
}

bool DebugEnabled() {
    return g_log_level == LOG_DEBUG;
}

void DebugLog(const std::string &msg) {
    if (g_log_level != LOG_DEBUG) {
        return;
    }
    LogInternal(LOG_DEBUG, std::string("[debug] ") + msg);
}

void SetLogLevel(LogLevel level) {
    g_log_level = level;
    g_debug_enabled = (level == LOG_DEBUG);
}

LogLevel GetLogLevel() {
    return g_log_level;
}

bool SetLogLevelFromString(const std::string &level) {
    std::string lowered = ToLower(level);
    if (lowered == "debug") {
        g_log_level = LOG_DEBUG;
    } else if (lowered == "info") {
        g_log_level = LOG_INFO;
    } else if (lowered == "warn") {
        g_log_level = LOG_WARN;
    } else if (lowered == "error") {
        g_log_level = LOG_ERROR;
    } else {
        return false;
    }
    g_debug_enabled = (g_log_level == LOG_DEBUG);
    return true;
}

void SetControllerLogger(ControllerLogger *logger) {
    g_controller_logger = logger;
}

static std::string EscapeLogMessage(const std::string &msg) {
    std::string out;
    out.reserve(msg.size());
    for (size_t i = 0; i < msg.size(); ++i) {
        char c = msg[i];
        if (c == '\n' || c == '\r') {
            out.push_back(' ');
        } else {
            out.push_back(c);
        }
    }
    return out;
}

void LogInternal(LogLevel level, const std::string &msg) {
    if (level < g_log_level) {
        return;
    }
    std::string safe = EscapeLogMessage(msg);
    if (g_controller_logger) {
        g_controller_logger->Log(level, safe);
        return;
    }
    std::cerr << safe << "\n";
}

void LogInfo(const std::string &msg) {
    LogInternal(LOG_INFO, msg);
}

void LogWarn(const std::string &msg) {
    LogInternal(LOG_WARN, msg);
}

void LogError(const std::string &msg) {
    LogInternal(LOG_ERROR, msg);
}

} // namespace gravastar
