#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "dns_server.h"
#include "local_records.h"
#include "query_logger.h"
#include "upstream_resolver.h"
#include "util.h"

#include <cstdlib>
#include <iostream>
#include <set>
#include <vector>

namespace {

std::string JoinPath(const std::string &dir, const std::string &path) {
    if (path.empty()) {
        return dir;
    }
    if (!path.empty() && path[0] == '/') {
        return path;
    }
    if (!dir.empty() && dir[dir.size() - 1] == '/') {
        return dir + path;
    }
    return dir + "/" + path;
}

void PrintUsage(const char *argv0) {
    std::cerr << "Usage: " << argv0 << " [-c config_dir] [-d]\n";
}

} // namespace

int main(int argc, char **argv) {
    std::string config_dir = "/etc/gravastar";
    bool debug = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) {
            config_dir = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            debug = true;
        } else if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        } else {
            PrintUsage(argv[0]);
            return 1;
        }
    }

    gravastar::SetDebugEnabled(debug);
    if (debug) {
        gravastar::DebugLog("Debug logging enabled.");
        gravastar::DebugLog("Using config directory: " + config_dir);
    }

    gravastar::ServerConfig config;
    std::string err;
    std::string main_path = JoinPath(config_dir, "gravastar.toml");
    if (!gravastar::ConfigLoader::LoadMainConfig(main_path, &config, &err)) {
        std::cerr << "Config error: " << err << "\n";
        return 1;
    }

    std::set<std::string> block_domains;
    std::string block_path = JoinPath(config_dir, config.blocklist_file);
    if (!gravastar::ConfigLoader::LoadBlocklist(block_path, &block_domains, &err)) {
        std::cerr << "Blocklist error: " << err << "\n";
        return 1;
    }

    std::vector<gravastar::LocalRecord> local_records_vec;
    std::string local_path = JoinPath(config_dir, config.local_records_file);
    if (!gravastar::ConfigLoader::LoadLocalRecords(local_path, &local_records_vec, &err)) {
        std::cerr << "Local records error: " << err << "\n";
        return 1;
    }

    std::vector<std::string> udp_servers;
    std::vector<std::string> dot_servers;
    std::string upstream_path = JoinPath(config_dir, config.upstreams_file);
    if (!gravastar::ConfigLoader::LoadUpstreams(upstream_path, &udp_servers, &dot_servers, &err)) {
        std::cerr << "Upstreams error: " << err << "\n";
        return 1;
    }

    if (!dot_servers.empty()) {
        std::cerr << "Note: DoT servers configured but TLS is not implemented yet.\n";
    }

    gravastar::Blocklist blocklist;
    blocklist.SetDomains(block_domains);

    gravastar::LocalRecords local_records;
    local_records.Load(local_records_vec);

    gravastar::DnsCache cache(config.cache_size_bytes, config.cache_ttl_sec);

    gravastar::UpstreamResolver resolver;
    resolver.SetUdpServers(udp_servers);
    resolver.SetDotServers(dot_servers);

    std::string log_dir = "/var/log/gravastar";
    const char *env_log_dir = std::getenv("GRAVASTAR_LOG_DIR");
    if (env_log_dir && env_log_dir[0] != '\0') {
        log_dir = env_log_dir;
    }
    gravastar::QueryLogger logger(log_dir, 100 * 1024 * 1024);
    gravastar::DnsServer server(config, blocklist, local_records, &cache,
                                resolver, &logger);
    if (!server.Run()) {
        std::cerr << "Failed to start DNS server\n";
        return 1;
    }

    return 0;
}
