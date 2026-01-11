#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "dns_server.h"
#include "local_records.h"
#include "controller_logger.h"
#include "query_logger.h"
#include "upstream_blocklist.h"
#include "upstream_resolver.h"
#include "util.h"

#include <sys/stat.h>
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
    std::cerr << "Usage: " << argv0 << " [-c config_dir] [-u upstream_blocklists] [-d]\n";
}

} // namespace

int main(int argc, char **argv) {
    std::string config_dir = "/etc/gravastar";
    std::string upstream_blocklists_path;
    bool upstream_path_forced = false;
    bool debug = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" && i + 1 < argc) {
            config_dir = argv[++i];
        } else if (arg == "-u" && i + 1 < argc) {
            upstream_blocklists_path = argv[++i];
            upstream_path_forced = true;
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

    std::string log_dir = "/var/log/gravastar";
    const char *env_log_dir = std::getenv("GRAVASTAR_LOG_DIR");
    if (env_log_dir && env_log_dir[0] != '\0') {
        log_dir = env_log_dir;
    }
    gravastar::ControllerLogger controller_logger(log_dir, 100 * 1024 * 1024);
    gravastar::SetControllerLogger(&controller_logger);
    gravastar::SetLogLevel(gravastar::LOG_DEBUG);
    gravastar::SetDebugEnabled(debug);
    if (debug) {
        gravastar::DebugLog("Debug logging enabled.");
        gravastar::DebugLog("Using config directory: " + config_dir);
    }

    gravastar::ServerConfig config;
    std::string err;
    std::string main_path = JoinPath(config_dir, "gravastar.toml");
    if (!gravastar::ConfigLoader::LoadMainConfig(main_path, &config, &err)) {
        gravastar::LogError("Config error: " + err);
        std::cerr << "Config error: " << err << "\n";
        return 1;
    }
    gravastar::SetLogLevelFromString(config.log_level);
    if (debug) {
        gravastar::SetLogLevel(gravastar::LOG_DEBUG);
    }

    std::set<std::string> block_domains;
    std::string block_path = JoinPath(config_dir, config.blocklist_file);
    if (!gravastar::ConfigLoader::LoadBlocklist(block_path, &block_domains, &err)) {
        gravastar::LogError("Blocklist error: " + err);
        std::cerr << "Blocklist error: " << err << "\n";
        return 1;
    }

    std::vector<gravastar::LocalRecord> local_records_vec;
    std::string local_path = JoinPath(config_dir, config.local_records_file);
    if (!gravastar::ConfigLoader::LoadLocalRecords(local_path, &local_records_vec, &err)) {
        gravastar::LogError("Local records error: " + err);
        std::cerr << "Local records error: " << err << "\n";
        return 1;
    }

    std::vector<std::string> udp_servers;
    std::vector<std::string> dot_servers;
    std::string upstream_path = JoinPath(config_dir, config.upstreams_file);
    if (!gravastar::ConfigLoader::LoadUpstreams(upstream_path, &udp_servers, &dot_servers, &err)) {
        gravastar::LogError("Upstreams error: " + err);
        std::cerr << "Upstreams error: " << err << "\n";
        return 1;
    }

    if (!dot_servers.empty()) {
        gravastar::DebugLog("DoT servers configured.");
    }

    gravastar::Blocklist blocklist;
    blocklist.SetDomains(block_domains);

    gravastar::LocalRecords local_records;
    local_records.Load(local_records_vec);

    gravastar::DnsCache cache(config.cache_size_bytes, config.cache_ttl_sec);

    gravastar::UpstreamResolver resolver;
    resolver.SetUdpServers(udp_servers);
    resolver.SetDotServers(dot_servers);
    resolver.SetDotVerify(config.dot_verify);

    gravastar::QueryLogger logger(log_dir, 100 * 1024 * 1024);
    gravastar::DnsServer server(config, &blocklist, local_records, &cache,
                                resolver, &logger);

    bool upstream_mode = false;
    if (upstream_blocklists_path.empty()) {
        upstream_blocklists_path = JoinPath(config_dir, "upstream_blocklists.toml");
    }
    struct stat st;
    if (stat(upstream_blocklists_path.c_str(), &st) == 0) {
        upstream_mode = true;
    } else if (upstream_path_forced) {
        gravastar::LogError("Upstream blocklist config not found: " + upstream_blocklists_path);
        std::cerr << "Upstream blocklist config not found: "
                  << upstream_blocklists_path << "\n";
        return 1;
    }

    gravastar::UpstreamBlocklistUpdater *updater = NULL;
    gravastar::UpstreamBlocklistConfig upstream_config;
    if (upstream_mode) {
        std::string err;
        if (!gravastar::LoadUpstreamBlocklistConfig(upstream_blocklists_path,
                                                    &upstream_config, &err)) {
            gravastar::LogError("Upstream blocklist config error: " + err);
            std::cerr << "Upstream blocklist config error: " << err << "\n";
            return 1;
        }
        updater = new gravastar::UpstreamBlocklistUpdater(
            upstream_config, block_path, &blocklist);
        updater->Start();
    }
    if (!server.Run()) {
        gravastar::LogError("Failed to start DNS server");
        std::cerr << "Failed to start DNS server\n";
        if (updater) {
            updater->Stop();
            delete updater;
        }
        return 1;
    }

    if (updater) {
        updater->Stop();
        delete updater;
    }
    return 0;
}
