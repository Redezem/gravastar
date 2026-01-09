#ifndef GRAVASTAR_UTIL_H
#define GRAVASTAR_UTIL_H

#include <string>
#include <vector>

namespace gravastar {

std::string Trim(const std::string &s);
std::string ToLower(const std::string &s);
std::vector<std::string> Split(const std::string &s, char delim);
bool StartsWith(const std::string &s, const std::string &prefix);
void SetDebugEnabled(bool enabled);
bool DebugEnabled();
void DebugLog(const std::string &msg);

} // namespace gravastar

#endif // GRAVASTAR_UTIL_H
