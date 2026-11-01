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
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_AAAA = 28,
    DNS_TYPE_OPT = 41
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
std::vector<unsigned char> BuildPTRResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &target);
std::vector<unsigned char> BuildTXTResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &text);
std::vector<unsigned char> BuildMXResponse(const DnsHeader &query_header,
                                            const DnsQuestion &question,
                                            unsigned short preference,
                                            const std::string &exchange);
void PatchResponseId(std::vector<unsigned char> *packet, uint16_t id);
bool ExtractFirstPtrTarget(const std::vector<unsigned char> &packet,
                           std::string *out_name);
// Rewrites upstream answers that point at private/loopback/link-local/shared
// address-space ranges: A records to 0.0.0.0 and AAAA records to ::.
// Covers RFC1918, loopback, link-local, CGNAT (100.64/10), TEST-NET ranges,
// 0/8, and the IPv6 equivalents (loopback, ULA, link-local, ::, plus
// IPv4-mapped and 6to4 embeddings of the IPv4 private ranges).
bool RewritePrivateARecordsToZero(std::vector<unsigned char> *packet,
                                  bool *rewritten);
// True only if `response` is a response packet whose transaction ID and
// question section (name, type, class; case-insensitive) match `query`.
// Guards against accepting an unrelated or spoofed upstream reply.
bool ValidateResponseMatchesQuery(const std::vector<unsigned char> &response,
                                  const std::vector<unsigned char> &query);
// Smallest record TTL present in the response (ANS/ADD sections; OPT records
// are skipped; a zero TTL yields *min_ttl = 0, meaning do-not-cache).
// Returns false when the packet has no cacheable records.
bool GetResponseMinRecordTtl(const std::vector<unsigned char> &response,
                             unsigned int *min_ttl);

} // namespace gravastar

#endif // GRAVASTAR_DNS_PACKET_H
