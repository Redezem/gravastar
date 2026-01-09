#include "config.h"

#include <cstdio>
#include <fstream>

namespace {

bool WriteFile(const std::string &path, const std::string &contents) {
    std::ofstream out(path.c_str());
    if (!out.is_open()) {
        return false;
    }
    out << contents;
    return true;
}

} // namespace

bool TestConfig() {
    std::string main_path = "/tmp/gravastar_test_main.toml";
    std::string block_path = "/tmp/gravastar_test_block.toml";
    std::string local_path = "/tmp/gravastar_test_local.toml";
    std::string upstream_path = "/tmp/gravastar_test_up.toml";

    if (!WriteFile(main_path,
                   "listen_addr = \"127.0.0.1\"\n"
                   "listen_port = 8053\n"
                   "cache_size_mb = 1\n"
                   "cache_ttl_sec = 10\n"
                   "dot_verify = false\n"
                   "log_level = \"warn\"\n"
                   "blocklist_file = \"blocklist.toml\"\n"
                   "local_records_file = \"local_records.toml\"\n"
                   "upstreams_file = \"upstreams.toml\"\n")) {
        return false;
    }

    if (!WriteFile(block_path, "domains = [\"example.com\", \"ads.test\"]\n")) {
        return false;
    }

    if (!WriteFile(local_path,
                   "[[record]]\n"
                   "name = \"router.local\"\n"
                   "type = \"A\"\n"
                   "value = \"192.168.0.1\"\n")) {
        return false;
    }

    if (!WriteFile(upstream_path,
                   "udp_servers = [\"1.1.1.1\", \"9.9.9.9\"]\n"
                   "dot_servers = [\"dns.quad9.net\"]\n")) {
        return false;
    }

    gravastar::ServerConfig cfg;
    std::string err;
    if (!gravastar::ConfigLoader::LoadMainConfig(main_path, &cfg, &err)) {
        return false;
    }
    if (cfg.listen_port != 8053) {
        return false;
    }
    if (cfg.dot_verify) {
        return false;
    }
    if (cfg.log_level != "warn") {
        return false;
    }

    std::set<std::string> domains;
    if (!gravastar::ConfigLoader::LoadBlocklist(block_path, &domains, &err)) {
        return false;
    }
    if (domains.find("example.com") == domains.end()) {
        return false;
    }

    std::vector<gravastar::LocalRecord> records;
    if (!gravastar::ConfigLoader::LoadLocalRecords(local_path, &records, &err)) {
        return false;
    }
    if (records.size() != 1 || records[0].name != "router.local") {
        return false;
    }

    std::vector<std::string> udp;
    std::vector<std::string> dot;
    if (!gravastar::ConfigLoader::LoadUpstreams(upstream_path, &udp, &dot, &err)) {
        return false;
    }
    if (udp.size() != 2 || dot.size() != 1) {
        return false;
    }

    std::remove(main_path.c_str());
    std::remove(block_path.c_str());
    std::remove(local_path.c_str());
    std::remove(upstream_path.c_str());

    return true;
}
