#include "upstream_resolver.h"

#include "util.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace gravastar {

void UpstreamResolver::SetUdpServers(const std::vector<std::string> &servers) {
    udp_servers_ = servers;
}

void UpstreamResolver::SetDotServers(const std::vector<std::string> &servers) {
    dot_servers_ = servers;
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

} // namespace gravastar
