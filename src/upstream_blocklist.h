#ifndef GRAVASTAR_UPSTREAM_BLOCKLIST_H
#define GRAVASTAR_UPSTREAM_BLOCKLIST_H

#include "blocklist.h"

#include <pthread.h>
#include <set>
#include <string>
#include <vector>

namespace gravastar {

struct UpstreamBlocklistConfig {
    std::vector<std::string> urls;
    unsigned int update_interval_sec;
    std::string cache_dir;
};

bool LoadUpstreamBlocklistConfig(const std::string &path,
                                 UpstreamBlocklistConfig *out,
                                 std::string *err);

bool ParseUpstreamBlocklistContent(const std::string &content,
                                   std::set<std::string> *domains);

bool BuildBlocklistFromSources(const std::vector<std::string> &urls,
                               const std::string &cache_dir,
                               std::set<std::string> *domains,
                               std::string *err);

bool WriteBlocklistToml(const std::string &path,
                        const std::set<std::string> &domains,
                        std::string *err);

std::string CachePathForUrl(const std::string &cache_dir,
                            const std::string &url);

class UpstreamBlocklistUpdater {
public:
    UpstreamBlocklistUpdater(const UpstreamBlocklistConfig &config,
                             const std::string &custom_blocklist_path,
                             const std::string &output_path,
                             Blocklist *blocklist);
    ~UpstreamBlocklistUpdater();

    bool Start();
    void Stop();
    bool UpdateOnce();

private:
    static void *ThreadEntry(void *arg);
    void ThreadLoop();
    bool EnsureCacheDir();

    UpstreamBlocklistConfig config_;
    std::string custom_blocklist_path_;
    std::string output_path_;
    Blocklist *blocklist_;
    pthread_t thread_;
    pthread_mutex_t mutex_;
    pthread_cond_t cv_;
    bool running_;
};

} // namespace gravastar

#endif // GRAVASTAR_UPSTREAM_BLOCKLIST_H
