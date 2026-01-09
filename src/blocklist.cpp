#include "blocklist.h"

#include "util.h"

namespace gravastar {

Blocklist::Blocklist() {
    pthread_rwlock_init(&lock_, NULL);
}

Blocklist::~Blocklist() {
    pthread_rwlock_destroy(&lock_);
}

void Blocklist::SetDomains(const std::set<std::string> &domains) {
    pthread_rwlock_wrlock(&lock_);
    domains_ = domains;
    pthread_rwlock_unlock(&lock_);
}

bool Blocklist::IsBlocked(const std::string &name) const {
    pthread_rwlock_rdlock(&lock_);
    if (domains_.empty()) {
        pthread_rwlock_unlock(&lock_);
        return false;
    }
    std::string canon = ToLower(name);
    if (!canon.empty() && canon[canon.size() - 1] == '.') {
        canon.resize(canon.size() - 1);
    }
    if (domains_.find(canon) != domains_.end()) {
        pthread_rwlock_unlock(&lock_);
        return true;
    }
    std::vector<std::string> labels = Split(canon, '.');
    if (labels.size() < 2) {
        pthread_rwlock_unlock(&lock_);
        return false;
    }
    for (size_t i = 1; i < labels.size(); ++i) {
        std::string suffix = labels[i];
        for (size_t j = i + 1; j < labels.size(); ++j) {
            suffix.append(".");
            suffix.append(labels[j]);
        }
        if (domains_.find(suffix) != domains_.end()) {
            pthread_rwlock_unlock(&lock_);
            return true;
        }
    }
    pthread_rwlock_unlock(&lock_);
    return false;
}

} // namespace gravastar
