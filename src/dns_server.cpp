#include "dns_server.h"

#include "dns_packet.h"
#include "util.h"

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sstream>
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

std::string QTypeToString(unsigned short qtype) {
  if (qtype == DNS_TYPE_A) {
    return "A";
  }
  if (qtype == DNS_TYPE_AAAA) {
    return "AAAA";
  }
  if (qtype == DNS_TYPE_CNAME) {
    return "CNAME";
  }
  if (qtype == DNS_TYPE_PTR) {
    return "PTR";
  }
  std::ostringstream out;
  out << "TYPE" << qtype;
  return out.str();
}

} // namespace

DnsServer::DnsServer(const ServerConfig &config, const Blocklist &blocklist,
                     const LocalRecords &local_records, DnsCache *cache,
                     const UpstreamResolver &resolver, QueryLogger *logger)
    : config_(config), blocklist_(blocklist), local_records_(local_records),
      cache_(cache), resolver_(resolver), logger_(logger), sock_(-1),
      running_(false), worker_count_(4) {
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
    DebugLog(std::string("socket() failed: ") + std::strerror(errno));
    return false;
  }
  int enable = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    DebugLog(std::string("fcntl(O_NONBLOCK) failed: ") + std::strerror(errno));
    close(sock);
    return false;
  }

  struct sockaddr_in addr;
  std::memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(config_.listen_port);
  if (inet_pton(AF_INET, config_.listen_addr.c_str(), &addr.sin_addr) != 1) {
    DebugLog(std::string("inet_pton failed for address: ") + config_.listen_addr);
    close(sock);
    return false;
  }

  if (bind(sock, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) <
      0) {
    DebugLog(std::string("bind() failed: ") + std::strerror(errno));
    close(sock);
    return false;
  }

  std::signal(SIGINT, HandleSignal);
  std::signal(SIGTERM, HandleSignal);

  sock_ = sock;
  running_ = true;
  {
    std::ostringstream out;
    out << "Listening on " << config_.listen_addr << ":" << config_.listen_port;
    DebugLog(out.str());
  }
  StartWorkers();
  {
    std::ostringstream out;
    out << "Worker threads started: " << workers_.size();
    DebugLog(out.str());
  }

  while (g_running) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (ready < 0) {
      DebugLog(std::string("select() failed: ") + std::strerror(errno));
      continue;
    }
    if (ready == 0) {
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
        DebugLog(std::string("recvfrom() failed: ") + std::strerror(errno));
        break;
      }
      if (received == 0) {
        continue;
      }
      if (DebugEnabled()) {
        char addr_buf[INET_ADDRSTRLEN];
        const char *addr_str = inet_ntop(AF_INET, &client_addr.sin_addr,
                                         addr_buf, sizeof(addr_buf));
        std::ostringstream out;
        out << "Received " << received << " bytes from "
            << (addr_str ? addr_str : "unknown") << ":" << ntohs(client_addr.sin_port);
        DebugLog(out.str());
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
    DebugLog("Failed to parse DNS query");
    return false;
  }
  if (DebugEnabled()) {
    std::ostringstream out;
    out << "Query: " << question.qname << " " << QTypeToString(question.qtype);
    DebugLog(out.str());
  }

  ResolveResult result;
  if (!ResolveQuery(packet, header, question, &result)) {
    return false;
  }

  if (!result.response.empty()) {
    if (result.source == RESOLVE_CACHE) {
      PatchResponseId(&result.response, header.id);
    }
    sendto(sock, &result.response[0], result.response.size(), 0,
           reinterpret_cast<const struct sockaddr *>(&client_addr), client_len);
  }

  if (logger_) {
    char addr_buf[INET_ADDRSTRLEN];
    const char *addr_str = inet_ntop(AF_INET, &client_addr.sin_addr, addr_buf,
                                     sizeof(addr_buf));
    std::string client_ip = addr_str ? addr_str : "unknown";
    std::string client_name = ResolveClientName(client_addr);
    std::string qtype = QTypeToString(question.qtype);
    if (result.source == RESOLVE_BLOCKLIST) {
      logger_->LogBlock(client_ip, client_name, question.qname, qtype);
    } else {
      std::string resolved_by;
      if (result.source == RESOLVE_LOCAL) {
        resolved_by = "local";
      } else if (result.source == RESOLVE_CACHE) {
        resolved_by = "cache";
      } else {
        resolved_by = "external";
      }
      logger_->LogPass(client_ip, client_name, question.qname, qtype,
                       resolved_by, result.upstream);
    }
  }

  return true;
}

bool DnsServer::ResolveQuery(const std::vector<unsigned char> &packet,
                             const DnsHeader &header,
                             const DnsQuestion &question,
                             ResolveResult *result) {
  if (!result) {
    return false;
  }
  result->response.clear();
  result->upstream.clear();
  result->source = RESOLVE_NONE;

  if (blocklist_.IsBlocked(question.qname)) {
    DebugLog("Blocklist match");
    result->source = RESOLVE_BLOCKLIST;
    if (question.qtype == DNS_TYPE_A) {
      result->response = BuildAResponse(header, question, "0.0.0.0");
    } else if (question.qtype == DNS_TYPE_AAAA) {
      result->response = BuildAAAAResponse(header, question, "::1");
    } else {
      result->response = BuildEmptyResponse(header, question);
    }
    return true;
  }

  std::string local_value;
  unsigned short local_type = 0;
  if (local_records_.Resolve(question.qname, question.qtype, &local_value,
                             &local_type)) {
    DebugLog("Local record match");
    result->source = RESOLVE_LOCAL;
    if (local_type == DNS_TYPE_A) {
      result->response = BuildAResponse(header, question, local_value);
    } else if (local_type == DNS_TYPE_AAAA) {
      result->response = BuildAAAAResponse(header, question, local_value);
    } else if (local_type == DNS_TYPE_CNAME) {
      result->response = BuildCNAMEResponse(header, question, local_value);
    }
    return true;
  }

  std::string key = MakeCacheKey(question.qname, question.qtype);
  std::vector<unsigned char> cached;
  if (cache_) {
    pthread_mutex_lock(&cache_mutex_);
    bool hit = cache_->Get(key, &cached);
    pthread_mutex_unlock(&cache_mutex_);
    if (hit) {
      DebugLog("Cache hit");
      result->source = RESOLVE_CACHE;
      result->response = cached;
      return true;
    }
    DebugLog("Cache miss");
  }

  result->source = RESOLVE_UPSTREAM;
  if (resolver_.ResolveUdp(packet, &result->response, &result->upstream)) {
    DebugLog("Upstream resolution success");
    if (cache_) {
      pthread_mutex_lock(&cache_mutex_);
      cache_->Put(key, result->response);
      pthread_mutex_unlock(&cache_mutex_);
    }
  } else {
    DebugLog("Upstream resolution failed");
    result->response = BuildEmptyResponse(header, question);
  }
  return true;
}

std::string DnsServer::ResolveClientName(const struct sockaddr_in &client_addr) {
  char addr_buf[INET_ADDRSTRLEN];
  const char *addr_str = inet_ntop(AF_INET, &client_addr.sin_addr, addr_buf,
                                   sizeof(addr_buf));
  if (!addr_str) {
    return "-";
  }
  std::vector<std::string> parts = Split(addr_str, '.');
  if (parts.size() != 4) {
    return "-";
  }
  std::ostringstream qname;
  qname << parts[3] << "." << parts[2] << "." << parts[1] << "." << parts[0]
        << ".in-addr.arpa";
  std::vector<unsigned char> query;
  query.reserve(64);
  unsigned short id = 0x4242;
  query.push_back(static_cast<unsigned char>((id >> 8) & 0xff));
  query.push_back(static_cast<unsigned char>(id & 0xff));
  query.push_back(0x01);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x01);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x00);
  query.push_back(0x00);
  std::string name = qname.str();
  size_t start = 0;
  while (start < name.size()) {
    size_t dot = name.find('.', start);
    if (dot == std::string::npos) {
      dot = name.size();
    }
    size_t len = dot - start;
    query.push_back(static_cast<unsigned char>(len));
    for (size_t i = 0; i < len; ++i) {
      query.push_back(static_cast<unsigned char>(name[start + i]));
    }
    start = dot + 1;
  }
  query.push_back(0);
  query.push_back(0x00);
  query.push_back(static_cast<unsigned char>(DNS_TYPE_PTR));
  query.push_back(0x00);
  query.push_back(0x01);

  DnsHeader header;
  DnsQuestion question;
  if (!ParseDnsQuery(query, &header, &question)) {
    return "-";
  }
  ResolveResult result;
  if (!ResolveQuery(query, header, question, &result)) {
    return "-";
  }
  std::string ptr_name;
  if (!ExtractFirstPtrTarget(result.response, &ptr_name)) {
    return "-";
  }
  if (ptr_name.empty()) {
    return "-";
  }
  return ptr_name;
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
