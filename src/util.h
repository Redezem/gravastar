#ifndef GRAVASTAR_UTIL_H
#define GRAVASTAR_UTIL_H

#include <string>
#include <vector>

#include <netinet/in.h>

namespace gravastar {

enum LogLevel {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3
};

std::string Trim(const std::string &s);
std::string ToLower(const std::string &s);
std::vector<std::string> Split(const std::string &s, char delim);
bool StartsWith(const std::string &s, const std::string &prefix);
// Replace characters that would break a space-separated single-line log field
// (control characters, space, DEL) with '_'.
std::string SanitizeLogField(const std::string &s);
// True if the client address matches any entry in `allowed` (exact IPv4 or
// CIDR notation). An empty list allows every client.
bool ClientAllowed(const struct sockaddr_in &client,
                   const std::vector<std::string> &allowed);
void SetDebugEnabled(bool enabled);
bool DebugEnabled();
void DebugLog(const std::string &msg);
void SetLogLevel(LogLevel level);
bool SetLogLevelFromString(const std::string &level);
LogLevel GetLogLevel();
void LogInfo(const std::string &msg);
void LogWarn(const std::string &msg);
void LogError(const std::string &msg);

class ControllerLogger;
void SetControllerLogger(ControllerLogger *logger);

} // namespace gravastar

#endif // GRAVASTAR_UTIL_H
