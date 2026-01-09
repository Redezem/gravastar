#ifndef GRAVASTAR_DNS_SERVER_H
#define GRAVASTAR_DNS_SERVER_H

#include "blocklist.h"
#include "cache.h"
#include "config.h"
#include "dns_packet.h"
#include "local_records.h"
#include "upstream_resolver.h"
#include "query_logger.h"

#include <netinet/in.h>
#include <pthread.h>
#include <deque>
#include <vector>

namespace gravastar {

class DnsServer {
public:
    DnsServer(const ServerConfig &config,
              Blocklist *blocklist,
              const LocalRecords &local_records,
              DnsCache *cache,
              const UpstreamResolver &resolver,
              QueryLogger *logger);
    ~DnsServer();

    bool Run();

private:
    enum ResolveSource {
        RESOLVE_BLOCKLIST,
        RESOLVE_LOCAL,
        RESOLVE_CACHE,
        RESOLVE_UPSTREAM,
        RESOLVE_NONE
    };

    struct ResolveResult {
        std::vector<unsigned char> response;
        ResolveSource source;
        std::string upstream;
    };

    struct Job {
        std::vector<unsigned char> packet;
        struct sockaddr_in client_addr;
        socklen_t client_len;
    };

    bool HandleQuery(int sock, const std::vector<unsigned char> &packet,
                     const struct sockaddr_in &client_addr, socklen_t client_len);
    bool ResolveQuery(const std::vector<unsigned char> &packet,
                      const DnsHeader &header,
                      const DnsQuestion &question,
                      ResolveResult *result);
    std::string ResolveClientName(const struct sockaddr_in &client_addr);
    void StartWorkers();
    void StopWorkers();
    void Enqueue(const Job &job);
    bool Dequeue(Job *job);
    static void *WorkerEntry(void *arg);
    void WorkerLoop();

    ServerConfig config_;
    Blocklist *blocklist_;
    LocalRecords local_records_;
    DnsCache *cache_;
    UpstreamResolver resolver_;
    QueryLogger *logger_;
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
