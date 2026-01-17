#include "dns_packet.h"

#include <string>
#include <vector>

namespace {

void WriteU16(std::vector<unsigned char> *buf, unsigned short value) {
    buf->push_back(static_cast<unsigned char>((value >> 8) & 0xff));
    buf->push_back(static_cast<unsigned char>(value & 0xff));
}

void WriteU32(std::vector<unsigned char> *buf, unsigned int value) {
    buf->push_back(static_cast<unsigned char>((value >> 24) & 0xff));
    buf->push_back(static_cast<unsigned char>((value >> 16) & 0xff));
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

std::vector<unsigned char> BuildPtrResponse() {
    std::vector<unsigned char> buf;
    WriteU16(&buf, 0x9999);
    WriteU16(&buf, 0x8180);
    WriteU16(&buf, 1);
    WriteU16(&buf, 1);
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    WriteQName(&buf, "4.3.2.1.in-addr.arpa");
    WriteU16(&buf, gravastar::DNS_TYPE_PTR);
    WriteU16(&buf, 1);
    buf.push_back(0xC0);
    buf.push_back(0x0C);
    WriteU16(&buf, gravastar::DNS_TYPE_PTR);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    std::vector<unsigned char> rdata;
    WriteQName(&rdata, "host.example.com");
    WriteU16(&buf, static_cast<unsigned short>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
    return buf;
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
    std::vector<unsigned char> txt = gravastar::BuildTXTResponse(header, question, "hello");
    if (txt.size() < query.size()) {
        return false;
    }
    std::vector<unsigned char> mx = gravastar::BuildMXResponse(header, question, 10, "mail.example.com");
    if (mx.size() < query.size()) {
        return false;
    }
    std::vector<unsigned char> ptr = gravastar::BuildPTRResponse(header, question, "host.example.com");
    if (ptr.size() < query.size()) {
        return false;
    }
    gravastar::PatchResponseId(&resp, 0xBEEF);
    if (ReadU16(resp, 0) != 0xBEEF) {
        return false;
    }
    std::vector<unsigned char> ptr_resp = BuildPtrResponse();
    std::string ptr_name;
    if (!gravastar::ExtractFirstPtrTarget(ptr_resp, &ptr_name)) {
        return false;
    }
    if (ptr_name != "host.example.com") {
        return false;
    }
    return true;
}
