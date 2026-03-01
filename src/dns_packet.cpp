#include "dns_packet.h"

#include <arpa/inet.h>
#include <cstring>
#include <sys/socket.h>

namespace gravastar {

namespace {

uint16_t ReadU16(const std::vector<unsigned char> &buf, size_t offset) {
    return static_cast<uint16_t>(buf[offset] << 8 | buf[offset + 1]);
}

void WriteU16(std::vector<unsigned char> *buf, uint16_t value) {
    buf->push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    buf->push_back(static_cast<unsigned char>(value & 0xff));
}

void WriteU32(std::vector<unsigned char> *buf, uint32_t value) {
    buf->push_back(static_cast<unsigned char>((value >> 24) & 0xff));
    buf->push_back(static_cast<unsigned char>((value >> 16) & 0xff));
    buf->push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    buf->push_back(static_cast<unsigned char>(value & 0xff));
}

bool ParseQName(const std::vector<unsigned char> &packet, size_t offset, std::string *out, size_t *end_offset) {
    std::string name;
    size_t pos = offset;
    while (pos < packet.size()) {
        unsigned char len = packet[pos++];
        if (len == 0) {
            break;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        if (pos + len > packet.size()) {
            return false;
        }
        if (!name.empty()) {
            name.append(".");
        }
        name.append(reinterpret_cast<const char *>(&packet[pos]), len);
        pos += len;
    }
    if (pos > packet.size()) {
        return false;
    }
    if (end_offset) {
        *end_offset = pos;
    }
    if (out) {
        *out = name;
    }
    return true;
}

void WriteQName(std::vector<unsigned char> *buf, const std::string &name) {
    if (name.empty()) {
        buf->push_back(0);
        return;
    }
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) {
            dot = name.size();
        }
        size_t len = dot - start;
        buf->push_back(static_cast<unsigned char>(len));
        for (size_t i = 0; i < len; ++i) {
            buf->push_back(static_cast<unsigned char>(name[start + i]));
        }
        start = dot + 1;
    }
    buf->push_back(0);
}

uint16_t ResponseFlags(const DnsHeader &query_header) {
    uint16_t flags = 0x8000; // QR
    flags |= (query_header.flags & 0x0100); // RD
    flags |= 0x0080; // RA
    return flags;
}

std::vector<unsigned char> BuildResponseHeader(const DnsHeader &query_header,
                                               uint16_t qdcount,
                                               uint16_t ancount) {
    std::vector<unsigned char> buf;
    buf.reserve(12);
    WriteU16(&buf, query_header.id);
    WriteU16(&buf, ResponseFlags(query_header));
    WriteU16(&buf, qdcount);
    WriteU16(&buf, ancount);
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    return buf;
}

void AppendQuestion(std::vector<unsigned char> *buf, const DnsQuestion &question) {
    WriteQName(buf, question.qname);
    WriteU16(buf, question.qtype);
    WriteU16(buf, question.qclass);
}

bool ReadName(const std::vector<unsigned char> &packet,
              size_t offset,
              std::string *out,
              size_t *end_offset,
              int depth) {
    if (depth > 16) {
        return false;
    }
    size_t pos = offset;
    size_t jump_end = offset;
    bool jumped = false;
    std::string name;
    while (pos < packet.size()) {
        unsigned char len = packet[pos];
        if (len == 0) {
            pos += 1;
            if (!jumped && end_offset) {
                *end_offset = pos;
            } else if (jumped && end_offset) {
                *end_offset = jump_end;
            }
            if (out) {
                *out = name;
            }
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet.size()) {
                return false;
            }
            uint16_t ptr = static_cast<uint16_t>((len & 0x3F) << 8) |
                           static_cast<uint16_t>(packet[pos + 1]);
            if (!jumped) {
                jump_end = pos + 2;
            }
            pos = ptr;
            jumped = true;
            depth += 1;
            if (depth > 16) {
                return false;
            }
            continue;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        pos += 1;
        if (pos + len > packet.size()) {
            return false;
        }
        if (!name.empty()) {
            name.append(".");
        }
        name.append(reinterpret_cast<const char *>(&packet[pos]), len);
        pos += len;
    }
    return false;
}

bool IsPrivateIPv4(const unsigned char *addr) {
    if (!addr) {
        return false;
    }
    if (addr[0] == 10) {
        return true;
    }
    if (addr[0] == 192 && addr[1] == 168) {
        return true;
    }
    if (addr[0] == 172 && addr[1] >= 16 && addr[1] <= 31) {
        return true;
    }
    return false;
}

} // namespace

bool ParseDnsQuery(const std::vector<unsigned char> &packet, DnsHeader *header, DnsQuestion *question) {
    if (packet.size() < 12) {
        return false;
    }
    if (header) {
        header->id = ReadU16(packet, 0);
        header->flags = ReadU16(packet, 2);
        header->qdcount = ReadU16(packet, 4);
        header->ancount = ReadU16(packet, 6);
        header->nscount = ReadU16(packet, 8);
        header->arcount = ReadU16(packet, 10);
    }
    if (!question) {
        return true;
    }
    if (ReadU16(packet, 4) == 0) {
        return false;
    }
    size_t offset = 12;
    size_t end = 0;
    std::string qname;
    if (!ParseQName(packet, offset, &qname, &end)) {
        return false;
    }
    if (end + 4 > packet.size()) {
        return false;
    }
    question->qname = qname;
    question->qtype = ReadU16(packet, end);
    question->qclass = ReadU16(packet, end + 2);
    question->raw_offset = offset;
    question->raw_length = (end + 4) - offset;
    return true;
}

std::vector<unsigned char> BuildEmptyResponse(const DnsHeader &query_header,
                                              const DnsQuestion &question) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 0);
    AppendQuestion(&buf, question);
    return buf;
}

std::vector<unsigned char> BuildAResponse(const DnsHeader &query_header,
                                          const DnsQuestion &question,
                                          const std::string &ipv4) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_A);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    WriteU16(&buf, 4);
    unsigned char addr[4];
    if (inet_pton(AF_INET, ipv4.c_str(), addr) != 1) {
        std::memset(addr, 0, sizeof(addr));
    }
    buf.insert(buf.end(), addr, addr + 4);
    return buf;
}

std::vector<unsigned char> BuildAAAAResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &ipv6) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_AAAA);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    WriteU16(&buf, 16);
    unsigned char addr[16];
    if (inet_pton(AF_INET6, ipv6.c_str(), addr) != 1) {
        std::memset(addr, 0, sizeof(addr));
    }
    buf.insert(buf.end(), addr, addr + 16);
    return buf;
}

std::vector<unsigned char> BuildCNAMEResponse(const DnsHeader &query_header,
                                              const DnsQuestion &question,
                                              const std::string &target) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_CNAME);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    std::vector<unsigned char> cname;
    WriteQName(&cname, target);
    WriteU16(&buf, static_cast<uint16_t>(cname.size()));
    buf.insert(buf.end(), cname.begin(), cname.end());
    return buf;
}

std::vector<unsigned char> BuildPTRResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &target) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_PTR);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    std::vector<unsigned char> ptr;
    WriteQName(&ptr, target);
    WriteU16(&buf, static_cast<uint16_t>(ptr.size()));
    buf.insert(buf.end(), ptr.begin(), ptr.end());
    return buf;
}

std::vector<unsigned char> BuildTXTResponse(const DnsHeader &query_header,
                                             const DnsQuestion &question,
                                             const std::string &text) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_TXT);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    std::vector<unsigned char> rdata;
    if (text.empty()) {
        rdata.push_back(0);
    } else {
        size_t offset = 0;
        while (offset < text.size()) {
            size_t chunk = text.size() - offset;
            if (chunk > 255) {
                chunk = 255;
            }
            rdata.push_back(static_cast<unsigned char>(chunk));
            for (size_t i = 0; i < chunk; ++i) {
                rdata.push_back(static_cast<unsigned char>(text[offset + i]));
            }
            offset += chunk;
        }
    }
    WriteU16(&buf, static_cast<uint16_t>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
    return buf;
}

std::vector<unsigned char> BuildMXResponse(const DnsHeader &query_header,
                                            const DnsQuestion &question,
                                            unsigned short preference,
                                            const std::string &exchange) {
    std::vector<unsigned char> buf = BuildResponseHeader(query_header, 1, 1);
    AppendQuestion(&buf, question);
    WriteQName(&buf, question.qname);
    WriteU16(&buf, DNS_TYPE_MX);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    std::vector<unsigned char> rdata;
    WriteU16(&rdata, preference);
    WriteQName(&rdata, exchange);
    WriteU16(&buf, static_cast<uint16_t>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
    return buf;
}

bool RewritePrivateARecordsToZero(std::vector<unsigned char> *packet,
                                  bool *rewritten) {
    if (!packet || packet->size() < 12) {
        return false;
    }

    bool replaced = false;
    size_t offset = 12;
    uint16_t qdcount = ReadU16(*packet, 4);
    uint16_t ancount = ReadU16(*packet, 6);
    uint16_t nscount = ReadU16(*packet, 8);
    uint16_t arcount = ReadU16(*packet, 10);

    for (uint16_t i = 0; i < qdcount; ++i) {
        size_t end = 0;
        if (!ReadName(*packet, offset, NULL, &end, 0)) {
            return false;
        }
        if (end + 4 > packet->size()) {
            return false;
        }
        offset = end + 4;
    }

    unsigned long rr_count = static_cast<unsigned long>(ancount) +
                             static_cast<unsigned long>(nscount) +
                             static_cast<unsigned long>(arcount);
    for (unsigned long i = 0; i < rr_count; ++i) {
        size_t end = 0;
        if (!ReadName(*packet, offset, NULL, &end, 0)) {
            return false;
        }
        if (end + 10 > packet->size()) {
            return false;
        }
        uint16_t type = ReadU16(*packet, end);
        uint16_t rdlength = ReadU16(*packet, end + 8);
        size_t rdata_offset = end + 10;
        if (rdata_offset + rdlength > packet->size()) {
            return false;
        }
        if (type == DNS_TYPE_A && rdlength == 4) {
            unsigned char *addr = &((*packet)[rdata_offset]);
            if (IsPrivateIPv4(addr)) {
                addr[0] = 0;
                addr[1] = 0;
                addr[2] = 0;
                addr[3] = 0;
                replaced = true;
            }
        }
        offset = rdata_offset + rdlength;
    }

    if (rewritten) {
        *rewritten = replaced;
    }
    return true;
}

void PatchResponseId(std::vector<unsigned char> *packet, uint16_t id) {
    if (!packet || packet->size() < 2) {
        return;
    }
    (*packet)[0] = static_cast<unsigned char>((id >> 8) & 0xff);
    (*packet)[1] = static_cast<unsigned char>(id & 0xff);
}

bool ExtractFirstPtrTarget(const std::vector<unsigned char> &packet,
                           std::string *out_name) {
    if (packet.size() < 12) {
        return false;
    }
    uint16_t qdcount = ReadU16(packet, 4);
    uint16_t ancount = ReadU16(packet, 6);
    size_t offset = 12;
    for (uint16_t i = 0; i < qdcount; ++i) {
        std::string name;
        size_t end = 0;
        if (!ReadName(packet, offset, &name, &end, 0)) {
            return false;
        }
        if (end + 4 > packet.size()) {
            return false;
        }
        offset = end + 4;
    }
    for (uint16_t i = 0; i < ancount; ++i) {
        std::string name;
        size_t end = 0;
        if (!ReadName(packet, offset, &name, &end, 0)) {
            return false;
        }
        if (end + 10 > packet.size()) {
            return false;
        }
        uint16_t type = ReadU16(packet, end);
        uint16_t rdlength = ReadU16(packet, end + 8);
        size_t rdata_offset = end + 10;
        if (rdata_offset + rdlength > packet.size()) {
            return false;
        }
        if (type == DNS_TYPE_PTR) {
            std::string target;
            size_t r_end = 0;
            if (!ReadName(packet, rdata_offset, &target, &r_end, 0)) {
                return false;
            }
            if (out_name) {
                *out_name = target;
            }
            return true;
        }
        offset = rdata_offset + rdlength;
    }
    return false;
}

} // namespace gravastar
