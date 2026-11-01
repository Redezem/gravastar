#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "dns_server.h"
#include "local_records.h"
#include "controller_logger.h"
#include "query_logger.h"
#include "sandbox.h"
#include "upstream_blocklist.h"
#include "upstream_resolver.h"
#include "util.h"

#include <sys/stat.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
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

    gravastar::Blocklist blocklist;
    std::set<std::string> block_domains;
    std::string block_path = JoinPath(config_dir, config.blocklist_file);
    gravastar::LogInfo("Loading blocklist: " + block_path);
    if (!gravastar::ConfigLoader::LoadBlocklist(block_path, &block_domains, &err)) {
        gravastar::LogError("Blocklist error: " + err);
        std::cerr << "Blocklist error: " << err << "\n";
        return 1;
    }
    {
        std::ostringstream out;
        out << "Blocklist loaded: " << block_domains.size() << " domains";
        gravastar::LogInfo(out.str());
    }
    blocklist.SetDomains(block_domains);

    std::vector<gravastar::LocalRecord> local_records_vec;
    std::string local_path = JoinPath(config_dir, config.local_records_file);
    gravastar::LogInfo("Loading local records: " + local_path);
    if (!gravastar::ConfigLoader::LoadLocalRecords(local_path, &local_records_vec, &err)) {
        gravastar::LogError("Local records error: " + err);
        std::cerr << "Local records error: " << err << "\n";
        return 1;
    }

    std::vector<std::string> udp_servers;
    std::vector<std::string> dot_servers;
    std::string upstream_path = JoinPath(config_dir, config.upstreams_file);
    gravastar::LogInfo("Loading upstreams: " + upstream_path);
    if (!gravastar::ConfigLoader::LoadUpstreams(upstream_path, &udp_servers, &dot_servers, &err)) {
        gravastar::LogError("Upstreams error: " + err);
        std::cerr << "Upstreams error: " << err << "\n";
        return 1;
    }

    if (!dot_servers.empty()) {
        gravastar::DebugLog("DoT servers configured.");
    }

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
        std::string generated_path = JoinPath(upstream_config.cache_dir, "blocklist.generated.toml");
        updater = new gravastar::UpstreamBlocklistUpdater(
            upstream_config, block_path, generated_path, &blocklist);
    }

    // Bind first (port 53 needs root), then drop to the unprivileged daemon
    // user, then lock the process down. Everything that is opened lazily at
    // runtime must be covered by the sandbox: log files (rotation reopens and
    // forks gzip), generated blocklists, and CA bundles for DoT.
    {
        if (!server.Bind()) {
            gravastar::LogError("Failed to bind listen socket");
            std::cerr << "Failed to bind listen socket\n";
            return 1;
        }
        if (!gravastar::DropPrivileges(config.drop_priv_user)) {
            gravastar::LogError("Refusing to start: privilege drop failed");
            std::cerr << "Refusing to start: privilege drop failed\n";
            return 1;
        }
        std::vector<std::string> read_paths;
        read_paths.push_back(config_dir);
        read_paths.push_back("/etc/ssl");      // Linux CA store
        read_paths.push_back("/etc/openssl");  // OpenBSD CA store
        std::vector<std::string> rw_paths;
        rw_paths.push_back(log_dir);
        if (upstream_mode) {
            rw_paths.push_back(upstream_config.cache_dir);
        }
        std::vector<std::string> exec_paths;
        exec_paths.push_back("/usr/bin");
        if (!gravastar::ApplyOsSandbox(read_paths, rw_paths, exec_paths)) {
            gravastar::LogError("Refusing to start: OS sandbox could not be applied");
            std::cerr << "Refusing to start: OS sandbox could not be applied\n";
            return 1;
        }
        // Start helper threads last: their files and sockets are created
        // under the unprivileged user and inside the sandbox.
        if (updater) {
            updater->Start();
        }
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
