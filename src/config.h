#ifndef GRAVASTAR_CONFIG_H
#define GRAVASTAR_CONFIG_H

#include <set>
#include <string>
#include <vector>

namespace gravastar {

struct ServerConfig {
    std::string listen_addr;
    unsigned short listen_port;
    size_t cache_size_bytes;
    unsigned int cache_ttl_sec;
    bool dot_verify;
    bool rebind_protection;
    std::string log_level;
    std::string blocklist_file;
    std::string local_records_file;
    std::string upstreams_file;
};

struct LocalRecord {
    std::string name;
    std::string type;
    std::string value;
};

class ConfigLoader {
public:
    static bool LoadMainConfig(const std::string &path, ServerConfig *out, std::string *err);
    static bool LoadBlocklist(const std::string &path, std::set<std::string> *out, std::string *err);
    static bool LoadLocalRecords(const std::string &path, std::vector<LocalRecord> *out, std::string *err);
    static bool LoadUpstreams(const std::string &path,
                              std::vector<std::string> *udp_out,
                              std::vector<std::string> *dot_out,
                              std::string *err);
};

} // namespace gravastar

#endif // GRAVASTAR_CONFIG_H
