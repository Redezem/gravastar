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

std::vector<unsigned char> BuildRawAnswer(
    const std::string &qname, unsigned short qtype,
    const std::vector<std::vector<unsigned char> > &rdatas,
    const std::vector<unsigned int> &ttls,
    const std::vector<unsigned short> &types) {
    std::vector<unsigned char> buf;
    WriteU16(&buf, 0x9999);
    WriteU16(&buf, 0x8180);
    WriteU16(&buf, 1);
    WriteU16(&buf, static_cast<unsigned short>(rdatas.size()));
    WriteU16(&buf, 0);
    WriteU16(&buf, 0);
    WriteQName(&buf, qname);
    WriteU16(&buf, qtype);
    WriteU16(&buf, 1);
    for (size_t i = 0; i < rdatas.size(); ++i) {
        buf.push_back(0xC0);
        buf.push_back(0x0C);
        WriteU16(&buf, types[i]);
        WriteU16(&buf, 1);
        WriteU32(&buf, ttls[i]);
        WriteU16(&buf, static_cast<unsigned short>(rdatas[i].size()));
        buf.insert(buf.end(), rdatas[i].begin(), rdatas[i].end());
    }
    return buf;
}

std::vector<unsigned char> V4(const std::string &dotted) {
    std::vector<unsigned char> out;
    size_t start = 0;
    for (int part = 0; part < 4; ++part) {
        size_t dot = dotted.find('.', start);
        if (dot == std::string::npos) {
            dot = dotted.size();
        }
        unsigned int v = 0;
        for (size_t i = start; i < dot; ++i) {
            v = v * 10 + static_cast<unsigned int>(dotted[i] - '0');
        }
        out.push_back(static_cast<unsigned char>(v));
        start = dot + 1;
    }
    return out;
}

std::vector<unsigned char> V6(int a, int b, int c, int d) {
    std::vector<unsigned char> out(16, 0);
    out[0] = static_cast<unsigned char>((a >> 8) & 0xff);
    out[1] = static_cast<unsigned char>(a & 0xff);
    out[2] = static_cast<unsigned char>((b >> 8) & 0xff);
    out[3] = static_cast<unsigned char>(b & 0xff);
    out[4] = static_cast<unsigned char>((c >> 8) & 0xff);
    out[5] = static_cast<unsigned char>(c & 0xff);
    out[6] = static_cast<unsigned char>((d >> 8) & 0xff);
    out[7] = static_cast<unsigned char>(d & 0xff);
    return out;
}

bool CollectTypedOffsets(const std::vector<unsigned char> &packet,
                         unsigned short want_type, unsigned short want_rdlen,
                         std::vector<size_t> *offsets) {
    if (!offsets || packet.size() < 12) {
        return false;
    }
    size_t offset = 12;
    unsigned short qdcount = ReadU16(packet, 4);
    unsigned long rr_count = static_cast<unsigned long>(ReadU16(packet, 6)) +
                             static_cast<unsigned long>(ReadU16(packet, 8)) +
                             static_cast<unsigned long>(ReadU16(packet, 10));
    for (unsigned short i = 0; i < qdcount; ++i) {
        size_t end = 0;
        if (!SkipName(packet, offset, &end) || end + 4 > packet.size()) {
            return false;
        }
        offset = end + 4;
    }
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
        if (type == want_type && rdlength == want_rdlen) {
            offsets->push_back(rdata_offset);
        }
        offset = rdata_offset + rdlength;
    }
    return true;
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

bool TestDnsRebindRanges() {
    // Extended IPv4 coverage (H1): loopback, CGNAT, link-local, 0/8, TEST-NETs,
    // benchmarking must all be zeroed; genuine public addresses untouched.
    std::vector<std::vector<unsigned char> > a_rdatas;
    a_rdatas.push_back(V4("127.0.0.1"));
    a_rdatas.push_back(V4("100.64.1.2"));
    a_rdatas.push_back(V4("100.127.255.255"));
    a_rdatas.push_back(V4("169.254.5.5"));
    a_rdatas.push_back(V4("0.1.2.3"));
    a_rdatas.push_back(V4("192.0.2.5"));
    a_rdatas.push_back(V4("198.18.0.7"));
    a_rdatas.push_back(V4("198.51.100.9"));
    a_rdatas.push_back(V4("203.0.113.4"));
    a_rdatas.push_back(V4("100.63.0.1"));   // just below CGNAT: public
    a_rdatas.push_back(V4("100.128.0.1"));  // just above CGNAT: public
    a_rdatas.push_back(V4("8.8.8.8"));
    std::vector<unsigned int> ttls(a_rdatas.size(), 60);
    std::vector<unsigned short> types(a_rdatas.size(), gravastar::DNS_TYPE_A);
    std::vector<unsigned char> pkt =
        BuildRawAnswer("wide-rebind.example", gravastar::DNS_TYPE_A,
                       a_rdatas, ttls, types);
    bool rewritten = false;
    if (!gravastar::RewritePrivateARecordsToZero(&pkt, &rewritten)) {
        return false;
    }
    if (!rewritten) {
        return false;
    }
    std::vector<size_t> a_offs;
    if (!CollectTypedOffsets(pkt, gravastar::DNS_TYPE_A, 4, &a_offs) ||
        a_offs.size() != a_rdatas.size()) {
        return false;
    }
    const int private_a[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};
    for (size_t i = 0; i < sizeof(private_a) / sizeof(private_a[0]); ++i) {
        size_t off = a_offs[private_a[i]];
        if (pkt[off] != 0 || pkt[off + 1] != 0 || pkt[off + 2] != 0 || pkt[off + 3] != 0) {
            return false;
        }
    }
    // Public ones survive: 100.63.0.1, 100.128.0.1, 8.8.8.8.
    const unsigned char expected_public[3][4] = {
        {100, 63, 0, 1}, {100, 128, 0, 1}, {8, 8, 8, 8}};
    for (size_t i = 0; i < 3; ++i) {
        size_t off = a_offs[9 + i];
        for (int b = 0; b < 4; ++b) {
            if (pkt[off + b] != expected_public[i][b]) {
                return false;
            }
        }
    }
    // Idempotent second pass.
    bool again = true;
    if (!gravastar::RewritePrivateARecordsToZero(&pkt, &again)) {
        return false;
    }
    if (again) {
        return false;
    }

    // IPv6 coverage: loopback, ULA, link-local, IPv4-mapped private must be
    // zeroed; public v6 and IPv4-mapped public untouched.
    std::vector<unsigned char> loop6(16, 0);
    loop6[15] = 1;
    std::vector<unsigned char> ula6 = V6(0xfd12, 0x3456, 0, 1);
    std::vector<unsigned char> ll6 = V6(0xfe80, 0, 0, 0xabcd);
    std::vector<unsigned char> mapped_priv(10, 0);
    mapped_priv.push_back(0xff);
    mapped_priv.push_back(0xff);
    std::vector<unsigned char> v4in = V4("192.168.10.10");
    mapped_priv.insert(mapped_priv.end(), v4in.begin(), v4in.end());
    std::vector<unsigned char> mapped_pub(10, 0);
    mapped_pub.push_back(0xff);
    mapped_pub.push_back(0xff);
    std::vector<unsigned char> v4pub = V4("1.1.1.1");
    mapped_pub.insert(mapped_pub.end(), v4pub.begin(), v4pub.end());
    std::vector<unsigned char> pub6 = V6(0x2001, 0x4860, 0x4860, 0x8844);

    std::vector<std::vector<unsigned char> > a6;
    a6.push_back(loop6);
    a6.push_back(ula6);
    a6.push_back(ll6);
    a6.push_back(mapped_priv);
    a6.push_back(mapped_pub);
    a6.push_back(pub6);
    std::vector<unsigned int> ttls6(a6.size(), 60);
    std::vector<unsigned short> types6(a6.size(), gravastar::DNS_TYPE_AAAA);
    std::vector<unsigned char> pkt6 =
        BuildRawAnswer("v6-rebind.example", gravastar::DNS_TYPE_AAAA,
                       a6, ttls6, types6);
    bool rewritten6 = false;
    if (!gravastar::RewritePrivateARecordsToZero(&pkt6, &rewritten6)) {
        return false;
    }
    if (!rewritten6) {
        return false;
    }
    std::vector<size_t> a6_offs;
    if (!CollectTypedOffsets(pkt6, gravastar::DNS_TYPE_AAAA, 16, &a6_offs) ||
        a6_offs.size() != a6.size()) {
        return false;
    }
    for (size_t i = 0; i < 4; ++i) {  // first four must be zeroed
        size_t off = a6_offs[i];
        for (int b = 0; b < 16; ++b) {
            if (pkt6[off + b] != 0) {
                return false;
            }
        }
    }
    // mapped_pub (index 4) still ends with 1.1.1.1; pub6 (index 5) intact.
    size_t off4 = a6_offs[4];
    if (pkt6[off4 + 12] != 1 || pkt6[off4 + 15] != 1) {
        return false;
    }
    size_t off5 = a6_offs[5];
    if (pkt6[off5] != 0x20 || pkt6[off5 + 1] != 0x01) {
        return false;
    }

    // A response packet must never parse as a query.
    gravastar::DnsHeader header;
    gravastar::DnsQuestion question;
    if (gravastar::ParseDnsQuery(pkt, &header, &question)) {
        return false;
    }
    return true;
}

bool TestDnsResponseValidation() {
    std::vector<unsigned char> query = BuildQuery("example.com", gravastar::DNS_TYPE_A);
    gravastar::DnsHeader header;
    gravastar::DnsQuestion question;
    if (!gravastar::ParseDnsQuery(query, &header, &question)) {
        return false;
    }
    std::vector<unsigned char> resp = gravastar::BuildAResponse(header, question, "1.2.3.4");
    if (!gravastar::ValidateResponseMatchesQuery(resp, query)) {
        return false;
    }
    // Case-insensitive name comparison.
    std::vector<unsigned char> query_caps = BuildQuery("EXAMPLE.COM", gravastar::DNS_TYPE_A);
    if (!gravastar::ValidateResponseMatchesQuery(resp, query_caps)) {
        return false;
    }
    // Transaction ID mismatch must fail.
    gravastar::PatchResponseId(&resp, 0x4242);
    if (gravastar::ValidateResponseMatchesQuery(resp, query)) {
        return false;
    }
    gravastar::PatchResponseId(&resp, 0x1234);
    // Different question name must fail.
    std::vector<unsigned char> other = BuildQuery("other.com", gravastar::DNS_TYPE_A);
    if (gravastar::ValidateResponseMatchesQuery(resp, other)) {
        return false;
    }
    // Different qtype must fail.
    std::vector<unsigned char> query_aaaa = BuildQuery("example.com", gravastar::DNS_TYPE_AAAA);
    if (gravastar::ValidateResponseMatchesQuery(resp, query_aaaa)) {
        return false;
    }
    // An echoed query (QR=0) must fail.
    if (gravastar::ValidateResponseMatchesQuery(query, query)) {
        return false;
    }
    return true;
}

bool TestDnsMinTtl() {
    std::vector<unsigned char> query = BuildQuery("ttl.example", gravastar::DNS_TYPE_A);
    gravastar::DnsHeader header;
    gravastar::DnsQuestion question;
    if (!gravastar::ParseDnsQuery(query, &header, &question)) {
        return false;
    }
    std::vector<unsigned char> resp = gravastar::BuildAResponse(header, question, "1.2.3.4");
    unsigned int ttl = 0;
    if (!gravastar::GetResponseMinRecordTtl(resp, &ttl) || ttl != 60) {
        return false;
    }
    // Mixed TTLs: minimum wins.
    std::vector<std::vector<unsigned char> > rdatas;
    rdatas.push_back(V4("1.1.1.1"));
    rdatas.push_back(V4("2.2.2.2"));
    std::vector<unsigned int> ttls;
    ttls.push_back(300);
    ttls.push_back(15);
    std::vector<unsigned short> types;
    types.push_back(gravastar::DNS_TYPE_A);
    types.push_back(gravastar::DNS_TYPE_A);
    std::vector<unsigned char> mixed =
        BuildRawAnswer("ttl.example", gravastar::DNS_TYPE_A, rdatas, ttls, types);
    if (!gravastar::GetResponseMinRecordTtl(mixed, &ttl) || ttl != 15) {
        return false;
    }
    // Zero TTL means do-not-cache.
    std::vector<unsigned int> ttls_zero;
    ttls_zero.push_back(300);
    ttls_zero.push_back(0);
    std::vector<unsigned char> with_zero =
        BuildRawAnswer("ttl.example", gravastar::DNS_TYPE_A, rdatas, ttls_zero, types);
    if (!gravastar::GetResponseMinRecordTtl(with_zero, &ttl) || ttl != 0) {
        return false;
    }
    return true;
}
