#include "blocklist.h"

#include "util.h"

namespace gravastar {

Blocklist::Blocklist() {}

void Blocklist::SetDomains(const std::set<std::string> &domains) {
    domains_ = domains;
}

bool Blocklist::IsBlocked(const std::string &name) const {
    if (domains_.empty()) {
        return false;
    }
    std::string canon = ToLower(name);
    if (!canon.empty() && canon[canon.size() - 1] == '.') {
        canon.resize(canon.size() - 1);
    }
    if (domains_.find(canon) != domains_.end()) {
        return true;
    }
    std::vector<std::string> labels = Split(canon, '.');
    if (labels.size() < 2) {
        return false;
    }
    for (size_t i = 1; i < labels.size(); ++i) {
        std::string suffix = labels[i];
        for (size_t j = i + 1; j < labels.size(); ++j) {
            suffix.append(".");
            suffix.append(labels[j]);
        }
        if (domains_.find(suffix) != domains_.end()) {
            return true;
        }
    }
    return false;
}

} // namespace gravastar
