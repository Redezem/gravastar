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

bool SkipName(const std::vector<unsigned char> &packet, size_t offset, size_t *end_offset) {
    size_t pos = offset;
    while (pos < packet.size()) {
        unsigned char len = packet[pos];
        if (len == 0) {
            if (end_offset) {
                *end_offset = pos + 1;
            }
            return true;
        }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet.size()) {
                return false;
            }
            if (end_offset) {
                *end_offset = pos + 2;
            }
            return true;
        }
        if ((len & 0xC0) != 0) {
            return false;
        }
        pos += 1;
        if (pos + len > packet.size()) {
            return false;
        }
        pos += len;
    }
    return false;
}

std::vector<unsigned char> BuildAResponseWithPrivateAndPublic() {
    std::vector<unsigned char> buf;
    WriteU16(&buf, 0x9999);
    WriteU16(&buf, 0x8180);
    WriteU16(&buf, 1);
    WriteU16(&buf, 2);
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    WriteQName(&buf, "example.com");
    WriteU16(&buf, gravastar::DNS_TYPE_A);
    WriteU16(&buf, 1);

    buf.push_back(0xC0);
    buf.push_back(0x0C);
    WriteU16(&buf, gravastar::DNS_TYPE_A);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    WriteU16(&buf, 4);
    buf.push_back(192);
    buf.push_back(168);
    buf.push_back(1);
    buf.push_back(10);

    buf.push_back(0xC0);
    buf.push_back(0x0C);
    WriteU16(&buf, gravastar::DNS_TYPE_A);
    WriteU16(&buf, 1);
    WriteU32(&buf, 60);
    WriteU16(&buf, 4);
    buf.push_back(8);
    buf.push_back(8);
    buf.push_back(8);
    buf.push_back(8);

    return buf;
}

bool CollectARecordOffsets(const std::vector<unsigned char> &packet,
                           std::vector<size_t> *offsets) {
    if (!offsets || packet.size() < 12) {
        return false;
    }
    size_t offset = 12;
    unsigned short qdcount = ReadU16(packet, 4);
    unsigned short ancount = ReadU16(packet, 6);
    unsigned short nscount = ReadU16(packet, 8);
    unsigned short arcount = ReadU16(packet, 10);
    for (unsigned short i = 0; i < qdcount; ++i) {
        size_t end = 0;
        if (!SkipName(packet, offset, &end) || end + 4 > packet.size()) {
            return false;
        }
        offset = end + 4;
    }

    unsigned long rr_count = static_cast<unsigned long>(ancount) +
                             static_cast<unsigned long>(nscount) +
                             static_cast<unsigned long>(arcount);
    for (unsigned long i = 0; i < rr_count; ++i) {
        size_t end = 0;
        if (!SkipName(packet, offset, &end) || end + 10 > packet.size()) {
            return false;
        }
        unsigned short type = ReadU16(packet, end);
        unsigned short rdlength = ReadU16(packet, end + 8);
        size_t rdata_offset = end + 10;
        if (rdata_offset + rdlength > packet.size()) {
            return false;
        }
        if (type == gravastar::DNS_TYPE_A && rdlength == 4) {
            offsets->push_back(rdata_offset);
        }
        offset = rdata_offset + rdlength;
    }
    return true;
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

    std::vector<unsigned char> upstream_resp = BuildAResponseWithPrivateAndPublic();
    std::vector<size_t> a_offsets;
    if (!CollectARecordOffsets(upstream_resp, &a_offsets)) {
        return false;
    }
    if (a_offsets.size() != 2) {
        return false;
    }
    if (upstream_resp[a_offsets[0]] != 192 || upstream_resp[a_offsets[0] + 1] != 168) {
        return false;
    }
    bool rewritten = false;
    if (!gravastar::RewritePrivateARecordsToZero(&upstream_resp, &rewritten)) {
        return false;
    }
    if (!rewritten) {
        return false;
    }
    if (upstream_resp[a_offsets[0]] != 0 || upstream_resp[a_offsets[0] + 1] != 0 ||
        upstream_resp[a_offsets[0] + 2] != 0 || upstream_resp[a_offsets[0] + 3] != 0) {
        return false;
    }
    if (upstream_resp[a_offsets[1]] != 8 || upstream_resp[a_offsets[1] + 1] != 8 ||
        upstream_resp[a_offsets[1] + 2] != 8 || upstream_resp[a_offsets[1] + 3] != 8) {
        return false;
    }

    bool rewritten_again = true;
    if (!gravastar::RewritePrivateARecordsToZero(&upstream_resp, &rewritten_again)) {
        return false;
    }
    if (rewritten_again) {
        return false;
    }
    return true;
}
