#include "upstream_resolver.h"

#include "util.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tls.h>
#include <unistd.h>

namespace gravastar {

namespace {

bool PathExists(const std::string &path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

bool IsDir(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

bool WaitForSocket(int fd, bool want_write, int timeout_sec) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    int ready = select(fd + 1, want_write ? NULL : &fds,
                       want_write ? &fds : NULL, NULL, &tv);
    return ready > 0;
}

bool TlsWriteAll(struct tls *ctx, int fd,
                 const unsigned char *data, size_t len,
                 int timeout_sec) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t wrote = tls_write(ctx, data + offset, len - offset);
        if (wrote > 0) {
            offset += static_cast<size_t>(wrote);
            continue;
        }
        if (wrote == TLS_WANT_POLLIN) {
            if (!WaitForSocket(fd, false, timeout_sec)) {
                return false;
            }
            continue;
        }
        if (wrote == TLS_WANT_POLLOUT) {
            if (!WaitForSocket(fd, true, timeout_sec)) {
                return false;
            }
            continue;
        }
        DebugLog(std::string("DoT tls_write failed: ") + tls_error(ctx));
        return false;
    }
    return true;
}

bool TlsReadAll(struct tls *ctx, int fd,
                unsigned char *data, size_t len,
                int timeout_sec) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t got = tls_read(ctx, data + offset, len - offset);
        if (got > 0) {
            offset += static_cast<size_t>(got);
            continue;
        }
        if (got == 0) {
            return false;
        }
        if (got == TLS_WANT_POLLIN) {
            if (!WaitForSocket(fd, false, timeout_sec)) {
                return false;
            }
            continue;
        }
        if (got == TLS_WANT_POLLOUT) {
            if (!WaitForSocket(fd, true, timeout_sec)) {
                return false;
            }
            continue;
        }
        DebugLog(std::string("DoT tls_read failed: ") + tls_error(ctx));
        return false;
    }
    return true;
}

bool ConnectTcp(const std::string &host, int port, int timeout_sec, int *out_fd) {
    if (!out_fd) {
        return false;
    }
    *out_fd = -1;
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::ostringstream port_str;
    port_str << port;
    struct addrinfo *res = NULL;
    if (getaddrinfo(host.c_str(), port_str.str().c_str(), &hints, &res) != 0) {
        return false;
    }
    int sock = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) {
            continue;
        }
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(sock);
            sock = -1;
            continue;
        }
        int rc = connect(sock, p->ai_addr, p->ai_addrlen);
        if (rc == 0) {
            // connected immediately
        } else if (errno == EINPROGRESS) {
            if (!WaitForSocket(sock, true, timeout_sec)) {
                close(sock);
                sock = -1;
                continue;
            }
            int err = 0;
            socklen_t err_len = sizeof(err);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0 ||
                err != 0) {
                close(sock);
                sock = -1;
                continue;
            }
        } else {
            close(sock);
            sock = -1;
            continue;
        }
        if (flags >= 0) {
            fcntl(sock, F_SETFL, flags);
        }
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        *out_fd = sock;
        break;
    }
    freeaddrinfo(res);
    return *out_fd >= 0;
}

bool ConfigureTls(struct tls_config *cfg) {
    if (!cfg) {
        return false;
    }
#ifdef __APPLE__
    if (PathExists("/opt/homebrew/etc/ssl/cert.pem")) {
        return tls_config_set_ca_file(cfg, "/opt/homebrew/etc/ssl/cert.pem") == 0;
    }
    if (PathExists("/usr/local/etc/ssl/cert.pem")) {
        return tls_config_set_ca_file(cfg, "/usr/local/etc/ssl/cert.pem") == 0;
    }
#endif
    if (IsDir("/etc/ssl/certs")) {
        return tls_config_set_ca_path(cfg, "/etc/ssl/certs") == 0;
    }
    if (PathExists("/etc/ssl/cert.pem")) {
        return tls_config_set_ca_file(cfg, "/etc/ssl/cert.pem") == 0;
    }
    if (PathExists("/etc/ssl/certs/ca-certificates.crt")) {
        return tls_config_set_ca_file(cfg, "/etc/ssl/certs/ca-certificates.crt") == 0;
    }
    return false;
}

bool ParseDotServer(const std::string &input,
                    std::string *tls_host,
                    std::string *connect_host,
                    int *port) {
    if (tls_host) {
        tls_host->clear();
    }
    if (connect_host) {
        connect_host->clear();
    }
    if (port) {
        *port = 853;
    }
    if (input.empty()) {
        return false;
    }
    size_t at = input.find('@');
    if (at == std::string::npos) {
        if (!ParseHostPort(input, 853, tls_host, port)) {
            return false;
        }
        if (connect_host) {
            *connect_host = *tls_host;
        }
        return true;
    }
    std::string left = input.substr(0, at);
    std::string right = input.substr(at + 1);
    if (left.empty() || right.empty()) {
        return false;
    }
    std::string addr;
    int p = 853;
    if (!ParseHostPort(right, 853, &addr, &p)) {
        return false;
    }
    if (tls_host) {
        *tls_host = left;
    }
    if (connect_host) {
        *connect_host = addr;
    }
    if (port) {
        *port = p;
    }
    return true;
}

} // namespace

bool ParseHostPort(const std::string &input,
                   int default_port,
                   std::string *host,
                   int *port) {
    if (host) {
        host->clear();
    }
    if (port) {
        *port = default_port;
    }
    if (input.empty()) {
        return false;
    }
    if (input[0] == '[') {
        size_t end = input.find(']');
        if (end == std::string::npos || end == 1) {
            return false;
        }
        std::string h = input.substr(1, end - 1);
        int p = default_port;
        if (end + 1 < input.size()) {
            if (input[end + 1] != ':') {
                return false;
            }
            std::string port_str = input.substr(end + 2);
            if (port_str.empty()) {
                return false;
            }
            std::istringstream iss(port_str);
            iss >> p;
            if (iss.fail() || p <= 0 || p > 65535) {
                return false;
            }
        }
        if (host) {
            *host = h;
        }
        if (port) {
            *port = p;
        }
        return true;
    }
    size_t colon = input.find_last_of(':');
    if (colon != std::string::npos && input.find(':') == colon) {
        std::string h = input.substr(0, colon);
        std::string port_str = input.substr(colon + 1);
        if (h.empty() || port_str.empty()) {
            return false;
        }
        int p = 0;
        std::istringstream iss(port_str);
        iss >> p;
        if (iss.fail() || p <= 0 || p > 65535) {
            return false;
        }
        if (host) {
            *host = h;
        }
        if (port) {
            *port = p;
        }
        return true;
    }
    if (host) {
        *host = input;
    }
    if (port) {
        *port = default_port;
    }
    return true;
}

UpstreamResolver::UpstreamResolver() : dot_verify_(true) {}

void UpstreamResolver::SetUdpServers(const std::vector<std::string> &servers) {
    udp_servers_ = servers;
}

void UpstreamResolver::SetDotServers(const std::vector<std::string> &servers) {
    dot_servers_ = servers;
}

void UpstreamResolver::SetDotVerify(bool verify) {
    dot_verify_ = verify;
}

bool UpstreamResolver::ResolveUdp(const std::vector<unsigned char> &query,
                                  std::vector<unsigned char> *response,
                                  std::string *used_server) {
    if (udp_servers_.empty()) {
        DebugLog("No upstream UDP servers configured");
        return false;
    }
    if (used_server) {
        *used_server = udp_servers_[0];
    }
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        DebugLog(std::string("upstream socket() failed: ") + std::strerror(errno));
        return false;
    }
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);

    if (inet_pton(AF_INET, udp_servers_[0].c_str(), &addr.sin_addr) != 1) {
        DebugLog(std::string("upstream inet_pton failed for: ") + udp_servers_[0]);
        close(sock);
        return false;
    }

    ssize_t sent = sendto(sock, &query[0], query.size(), 0,
                          reinterpret_cast<struct sockaddr *>(&addr),
                          sizeof(addr));
    if (sent < 0) {
        DebugLog(std::string("upstream sendto failed: ") + std::strerror(errno));
        close(sock);
        return false;
    }
    if (DebugEnabled()) {
        std::ostringstream out;
        out << "Upstream query sent to " << udp_servers_[0] << ":53";
        DebugLog(out.str());
    }

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (ready <= 0) {
        DebugLog("upstream select timed out or failed");
        close(sock);
        return false;
    }

    unsigned char buf[4096];
    ssize_t got = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    close(sock);
    if (got <= 0) {
        DebugLog("upstream recvfrom failed");
        return false;
    }
    if (DebugEnabled()) {
        std::ostringstream out;
        out << "Upstream response received: " << got << " bytes";
        DebugLog(out.str());
    }
    response->assign(buf, buf + got);
    return true;
}

bool UpstreamResolver::ResolveDot(const std::vector<unsigned char> &query,
                                  std::vector<unsigned char> *response,
                                  std::string *used_server) {
    if (dot_servers_.empty()) {
        return false;
    }
    static bool tls_inited = false;
    if (!tls_inited) {
        if (tls_init() != 0) {
            DebugLog("DoT tls_init failed");
            return false;
        }
        tls_inited = true;
    }
    std::string host;
    std::string connect_host;
    int port = 853;
    if (!ParseDotServer(dot_servers_[0], &host, &connect_host, &port)) {
        DebugLog(std::string("DoT invalid server: ") + dot_servers_[0]);
        return false;
    }
    if (connect_host.empty()) {
        connect_host = host;
    }
    if (used_server) {
        std::ostringstream out;
        out << host << "@" << connect_host << ":" << port;
        *used_server = out.str();
    }
    int sock = -1;
    if (!ConnectTcp(connect_host, port, 2, &sock)) {
        DebugLog(std::string("DoT connect failed: ") + connect_host);
        return false;
    }
    struct tls_config *cfg = tls_config_new();
    if (!cfg) {
        close(sock);
        return false;
    }
    bool insecure = !dot_verify_;
    if (!insecure && !ConfigureTls(cfg)) {
        DebugLog("DoT using insecure TLS config (no CA found)");
        tls_config_insecure_noverifycert(cfg);
        tls_config_insecure_noverifyname(cfg);
        insecure = true;
    }
    if (insecure) {
        DebugLog("DoT TLS verification disabled");
        tls_config_insecure_noverifycert(cfg);
        tls_config_insecure_noverifyname(cfg);
    }
    struct tls *ctx = tls_client();
    if (!ctx) {
        tls_config_free(cfg);
        close(sock);
        return false;
    }
    if (tls_configure(ctx, cfg) != 0) {
        DebugLog(std::string("DoT tls_configure failed: ") + tls_error(ctx));
        tls_free(ctx);
        tls_config_free(cfg);
        close(sock);
        return false;
    }
    tls_config_free(cfg);
    if (tls_connect_socket(ctx, sock, host.c_str()) != 0) {
        DebugLog(std::string("DoT tls_connect_socket failed: ") + tls_error(ctx));
        tls_free(ctx);
        close(sock);
        return false;
    }
    unsigned char len_buf[2];
    size_t qlen = query.size();
    if (qlen > 0xFFFF) {
        tls_close(ctx);
        tls_free(ctx);
        close(sock);
        return false;
    }
    len_buf[0] = static_cast<unsigned char>((qlen >> 8) & 0xff);
    len_buf[1] = static_cast<unsigned char>(qlen & 0xff);
    if (!TlsWriteAll(ctx, sock, len_buf, 2, 2) ||
        !TlsWriteAll(ctx, sock, &query[0], qlen, 2)) {
        tls_close(ctx);
        tls_free(ctx);
        close(sock);
        return false;
    }
    unsigned char resp_len_buf[2];
    if (!TlsReadAll(ctx, sock, resp_len_buf, 2, 2)) {
        tls_close(ctx);
        tls_free(ctx);
        close(sock);
        return false;
    }
    size_t resp_len = (static_cast<size_t>(resp_len_buf[0]) << 8) |
                      static_cast<size_t>(resp_len_buf[1]);
    if (resp_len == 0) {
        DebugLog("DoT response length is zero");
        tls_close(ctx);
        tls_free(ctx);
        close(sock);
        return false;
    }
    std::vector<unsigned char> buf(resp_len);
    if (!TlsReadAll(ctx, sock, &buf[0], resp_len, 2)) {
        tls_close(ctx);
        tls_free(ctx);
        close(sock);
        return false;
    }
    response->swap(buf);
    tls_close(ctx);
    tls_free(ctx);
    close(sock);
    return true;
}

} // namespace gravastar
