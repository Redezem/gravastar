#include "cache.h"

namespace gravastar {

DnsCache::DnsCache(size_t max_bytes, unsigned int ttl_sec)
    : max_bytes_(max_bytes), ttl_sec_(ttl_sec), current_bytes_(0) {}

void DnsCache::SetLimits(size_t max_bytes, unsigned int ttl_sec) {
    max_bytes_ = max_bytes;
    ttl_sec_ = ttl_sec;
    EvictIfNeeded();
}

bool DnsCache::Get(const std::string &key, std::vector<unsigned char> *out) {
    EvictExpired();
    std::map<std::string, Entry>::iterator it = entries_.find(key);
    if (it == entries_.end()) {
        return false;
    }
    lru_.erase(it->second.lru_it);
    lru_.push_back(key);
    it->second.lru_it = --lru_.end();
    if (out) {
        *out = it->second.response;
    }
    return true;
}

void DnsCache::Put(const std::string &key, const std::vector<unsigned char> &response) {
    EvictExpired();
    std::map<std::string, Entry>::iterator it = entries_.find(key);
    if (it != entries_.end()) {
        current_bytes_ -= it->second.size;
        lru_.erase(it->second.lru_it);
        entries_.erase(it);
    }
    Entry entry;
    entry.response = response;
    entry.size = response.size();
    entry.expiry = std::time(NULL) + ttl_sec_;
    lru_.push_back(key);
    entry.lru_it = --lru_.end();
    entries_[key] = entry;
    current_bytes_ += entry.size;
    EvictIfNeeded();
}

void DnsCache::EvictExpired() {
    time_t now = std::time(NULL);
    std::list<std::string>::iterator it = lru_.begin();
    while (it != lru_.end()) {
        std::map<std::string, Entry>::iterator entry_it = entries_.find(*it);
        if (entry_it == entries_.end()) {
            it = lru_.erase(it);
            continue;
        }
        if (entry_it->second.expiry <= now) {
            current_bytes_ -= entry_it->second.size;
            entries_.erase(entry_it);
            it = lru_.erase(it);
        } else {
            ++it;
        }
    }
}

void DnsCache::EvictIfNeeded() {
    while (current_bytes_ > max_bytes_ && !lru_.empty()) {
        std::string key = lru_.front();
        std::map<std::string, Entry>::iterator it = entries_.find(key);
        if (it != entries_.end()) {
            current_bytes_ -= it->second.size;
            entries_.erase(it);
        }
        lru_.pop_front();
    }
}

} // namespace gravastar
