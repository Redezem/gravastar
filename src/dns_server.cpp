#include "dns_server.h"

#include "dns_packet.h"
#include "util.h"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace gravastar {

namespace {

volatile sig_atomic_t g_running = 1;

void HandleSignal(int) { g_running = 0; }

std::string MakeCacheKey(const std::string &name, unsigned short qtype) {
  std::string key = ToLower(name);
  if (!key.empty() && key[key.size() - 1] == '.') {
    key.resize(key.size() - 1);
  }
  key.append("|");
  char buf[16];
  std::snprintf(buf, 16, "%u", static_cast<unsigned int>(qtype));
  key.append(buf);
  return key;
}

} // namespace

DnsServer::DnsServer(const ServerConfig &config, const Blocklist &blocklist,
                     const LocalRecords &local_records, DnsCache *cache,
                     const UpstreamResolver &resolver)
    : config_(config), blocklist_(blocklist), local_records_(local_records),
      cache_(cache), resolver_(resolver), sock_(-1), running_(false),
      worker_count_(4) {
  pthread_mutex_init(&queue_mutex_, NULL);
  pthread_cond_init(&queue_cv_, NULL);
  pthread_mutex_init(&cache_mutex_, NULL);
}

DnsServer::~DnsServer() {
  StopWorkers();
  pthread_mutex_destroy(&queue_mutex_);
  pthread_cond_destroy(&queue_cv_);
  pthread_mutex_destroy(&cache_mutex_);
}

bool DnsServer::Run() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    return false;
  }
  int enable = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(sock);
    return false;
  }

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(config_.listen_port);
  if (inet_pton(AF_INET, config_.listen_addr.c_str(), &addr.sin_addr) != 1) {
    close(sock);
    return false;
  }

  if (bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) <
      0) {
    close(sock);
    return false;
  }

  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);

  sock_ = sock;
  running_ = true;
  StartWorkers();

  while (g_running) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (ready <= 0) {
      continue;
    }
    if (!FD_ISSET(sock, &readfds)) {
      continue;
    }
    for (;;) {
      unsigned char buf[4096];
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof(client_addr);
      ssize_t received = recvfrom(
          sock, buf, sizeof(buf), 0,
          reinterpret_cast<struct sockaddr *>(&client_addr), &client_len);
      if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        break;
      }
      if (received == 0) {
        continue;
      }
      Job job;
      job.packet.assign(buf, buf + received);
      job.client_addr = client_addr;
      job.client_len = client_len;
      Enqueue(job);
    }
  }

  StopWorkers();
  close(sock);
  sock_ = -1;
  return true;
}

bool DnsServer::HandleQuery(int sock, const std::vector<unsigned char> &packet,
                            const struct sockaddr_in &client_addr,
                            socklen_t client_len) {
  DnsHeader header;
  DnsQuestion question;
  if (!ParseDnsQuery(packet, &header, &question)) {
    return false;
  }

  std::vector<unsigned char> response;

  if (blocklist_.IsBlocked(question.qname)) {
    if (question.qtype == DNS_TYPE_A) {
      response = BuildAResponse(header, question, "0.0.0.0");
    } else if (question.qtype == DNS_TYPE_AAAA) {
      response = BuildAAAAResponse(header, question, "::1");
    } else {
      response = BuildEmptyResponse(header, question);
    }
  } else {
    std::string local_value;
    unsigned short local_type = 0;
    if (local_records_.Resolve(question.qname, question.qtype, &local_value,
                               &local_type)) {
      if (local_type == DNS_TYPE_A) {
        response = BuildAResponse(header, question, local_value);
      } else if (local_type == DNS_TYPE_AAAA) {
        response = BuildAAAAResponse(header, question, local_value);
      } else if (local_type == DNS_TYPE_CNAME) {
        response = BuildCNAMEResponse(header, question, local_value);
      }
    } else {
      std::string key = MakeCacheKey(question.qname, question.qtype);
      std::vector<unsigned char> cached;
      if (cache_) {
        pthread_mutex_lock(&cache_mutex_);
        bool hit = cache_->Get(key, &cached);
        pthread_mutex_unlock(&cache_mutex_);
        if (hit) {
          response = cached;
        }
      }
      if (response.empty()) {
        if (resolver_.ResolveUdp(packet, &response)) {
          if (cache_) {
            pthread_mutex_lock(&cache_mutex_);
            cache_->Put(key, response);
            pthread_mutex_unlock(&cache_mutex_);
          }
        } else {
          response = BuildEmptyResponse(header, question);
        }
      }
    }
  }

  if (!response.empty()) {
    sendto(sock, &response[0], response.size(), 0,
           reinterpret_cast<const struct sockaddr *>(&client_addr), client_len);
  }

  return true;
}

void DnsServer::StartWorkers() {
  workers_.clear();
  for (size_t i = 0; i < worker_count_; ++i) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, WorkerEntry, this) == 0) {
      workers_.push_back(tid);
    }
  }
}

void DnsServer::StopWorkers() {
  pthread_mutex_lock(&queue_mutex_);
  running_ = false;
  pthread_cond_broadcast(&queue_cv_);
  pthread_mutex_unlock(&queue_mutex_);
  for (size_t i = 0; i < workers_.size(); ++i) {
    pthread_join(workers_[i], NULL);
  }
  workers_.clear();
}

void DnsServer::Enqueue(const Job &job) {
  pthread_mutex_lock(&queue_mutex_);
  queue_.push_back(job);
  pthread_cond_signal(&queue_cv_);
  pthread_mutex_unlock(&queue_mutex_);
}

bool DnsServer::Dequeue(Job *job) {
  pthread_mutex_lock(&queue_mutex_);
  while (queue_.empty() && running_) {
    pthread_cond_wait(&queue_cv_, &queue_mutex_);
  }
  if (!running_ && queue_.empty()) {
    pthread_mutex_unlock(&queue_mutex_);
    return false;
  }
  *job = queue_.front();
  queue_.pop_front();
  pthread_mutex_unlock(&queue_mutex_);
  return true;
}

void *DnsServer::WorkerEntry(void *arg) {
  DnsServer *server = static_cast<DnsServer *>(arg);
  server->WorkerLoop();
  return NULL;
}

void DnsServer::WorkerLoop() {
  for (;;) {
    Job job;
    if (!Dequeue(&job)) {
      break;
    }
    HandleQuery(sock_, job.packet, job.client_addr, job.client_len);
  }
}

} // namespace gravastar
