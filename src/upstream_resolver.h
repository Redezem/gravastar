#ifndef GRAVASTAR_UPSTREAM_RESOLVER_H
#define GRAVASTAR_UPSTREAM_RESOLVER_H

#include <string>
#include <vector>

namespace gravastar {

class UpstreamResolver {
public:
    void SetUdpServers(const std::vector<std::string> &servers);
    void SetDotServers(const std::vector<std::string> &servers);

    bool ResolveUdp(const std::vector<unsigned char> &query,
                    std::vector<unsigned char> *response,
                    std::string *used_server);

private:
    std::vector<std::string> udp_servers_;
    std::vector<std::string> dot_servers_;
};

} // namespace gravastar

#endif // GRAVASTAR_UPSTREAM_RESOLVER_H
