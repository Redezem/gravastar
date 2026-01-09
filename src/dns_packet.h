#ifndef GRAVASTAR_DNS_PACKET_H
#define GRAVASTAR_DNS_PACKET_H

#include <string>
#include <vector>

#include <stdint.h>

namespace gravastar {

enum {
    DNS_TYPE_A = 1,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_PTR = 12,
    DNS_TYPE_AAAA = 28
};

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct DnsQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
    size_t raw_offset;
    size_t raw_length;
};

bool ParseDnsQuery(const std::vector<unsigned char> &packet, DnsHeader *header, DnsQuestion *question);

std::vector<unsigned char> BuildEmptyResponse(const DnsHeader &query_header,
                                              const DnsQuestion &question);
std::vector<unsigned char> BuildAResponse(const DnsHeader &query_header,
                                          const DnsQuestion &question,
                                          const std::string &ipv4);
std::vector<unsigned char> BuildAAAAResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &ipv6);
std::vector<unsigned char> BuildCNAMEResponse(const DnsHeader &query_header,
                                              const DnsQuestion &question,
                                              const std::string &target);
void PatchResponseId(std::vector<unsigned char> *packet, uint16_t id);
bool ExtractFirstPtrTarget(const std::vector<unsigned char> &packet,
                           std::string *out_name);

} // namespace gravastar

#endif // GRAVASTAR_DNS_PACKET_H
