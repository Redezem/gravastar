#include "dns_packet.h"

#include <string>
#include <vector>

namespace {

void WriteU16(std::vector<unsigned char> *buf, unsigned short value) {
    buf->push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    buf->push_back(static_cast<unsigned char>(value & 0xff));
}

void WriteQName(std::vector<unsigned char> *buf, const std::string &name) {
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

std::vector<unsigned char> BuildQuery(const std::string &name, unsigned short qtype) {
    std::vector<unsigned char> buf;
    buf.reserve(64);
    WriteU16(&buf, 0x1234);
    WriteU16(&buf, 0x0100);
    WriteU16(&buf, 1);
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    WriteQName(&buf, name);
    WriteU16(&buf, qtype);
    WriteU16(&buf, 1);
    return buf;
}

unsigned short ReadU16(const std::vector<unsigned char> &buf, size_t offset) {
    return static_cast<unsigned short>((buf[offset] << 8) | buf[offset + 1]);
}

} // namespace

bool TestDnsPacket() {
    std::vector<unsigned char> query = BuildQuery("example.com", gravastar::DNS_TYPE_A);
    gravastar::DnsHeader header;
    gravastar::DnsQuestion question;
    if (!gravastar::ParseDnsQuery(query, &header, &question)) {
        return false;
    }
    if (question.qname != "example.com") {
        return false;
    }
    std::vector<unsigned char> resp = gravastar::BuildAResponse(header, question, "1.2.3.4");
    if (resp.size() < query.size()) {
        return false;
    }
    gravastar::PatchResponseId(&resp, 0xBEEF);
    if (ReadU16(resp, 0) != 0xBEEF) {
        return false;
    }
    return true;
}
