#include "dns_packet.h"

#include <arpa/inet.h>
#include <cstring>

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

} // namespace gravastar
