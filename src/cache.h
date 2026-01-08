#ifndef GRAVASTAR_CACHE_H
#define GRAVASTAR_CACHE_H

#include <ctime>
#include <list>
#include <map>
#include <string>
#include <vector>

namespace gravastar {

class DnsCache {
public:
    DnsCache(size_t max_bytes, unsigned int ttl_sec);
    void SetLimits(size_t max_bytes, unsigned int ttl_sec);

    bool Get(const std::string &key, std::vector<unsigned char> *out);
    void Put(const std::string &key, const std::vector<unsigned char> &response);

    size_t size_bytes() const { return current_bytes_; }
    size_t max_bytes() const { return max_bytes_; }

private:
    struct Entry {
        std::vector<unsigned char> response;
        time_t expiry;
        size_t size;
        std::list<std::string>::iterator lru_it;
    };

    void EvictExpired();
    void EvictIfNeeded();

    size_t max_bytes_;
    unsigned int ttl_sec_;
    size_t current_bytes_;
    std::list<std::string> lru_;
    std::map<std::string, Entry> entries_;
};

} // namespace gravastar

#endif // GRAVASTAR_CACHE_H
