#ifndef GRAVASTAR_DNS_SERVER_H
#define GRAVASTAR_DNS_SERVER_H

#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "local_records.h"
#include "upstream_resolver.h"

#include <netinet/in.h>
#include <pthread.h>
#include <deque>
#include <vector>

namespace gravastar {

class DnsServer {
public:
    DnsServer(const ServerConfig &config,
              const Blocklist &blocklist,
              const LocalRecords &local_records,
              DnsCache *cache,
              const UpstreamResolver &resolver);
    ~DnsServer();

    bool Run();

private:
    struct Job {
        std::vector<unsigned char> packet;
        struct sockaddr_in client_addr;
        socklen_t client_len;
    };

    bool HandleQuery(int sock, const std::vector<unsigned char> &packet,
                     const struct sockaddr_in &client_addr, socklen_t client_len);
    void StartWorkers();
    void StopWorkers();
    void Enqueue(const Job &job);
    bool Dequeue(Job *job);
    static void *WorkerEntry(void *arg);
    void WorkerLoop();

    ServerConfig config_;
    Blocklist blocklist_;
    LocalRecords local_records_;
    DnsCache *cache_;
    UpstreamResolver resolver_;
    int sock_;
    bool running_;
    size_t worker_count_;
    std::deque<Job> queue_;
    pthread_mutex_t queue_mutex_;
    pthread_cond_t queue_cv_;
    pthread_mutex_t cache_mutex_;
    std::vector<pthread_t> workers_;
};

} // namespace gravastar

#endif // GRAVASTAR_DNS_SERVER_H
