#include "local_records.h"

#include "dns_packet.h"
#include "util.h"

#include <cstdio>

namespace gravastar {

namespace {

std::string MakeKey(const std::string &name, unsigned short qtype) {
    std::string key = ToLower(name);
    if (!key.empty() && key[key.size() - 1] == '.') {
        key.resize(key.size() - 1);
    }
    key.append("|");
    char buf[16];
    std::snprintf(buf, 16, "%u", static_cast<unsigned int>(qtype));
    key.append(buf);
    return key;
}

unsigned short TypeFromString(const std::string &type) {
    if (type == "a") {
        return DNS_TYPE_A;
    }
    if (type == "aaaa") {
        return DNS_TYPE_AAAA;
    }
    if (type == "cname") {
        return DNS_TYPE_CNAME;
    }
    if (type == "ptr") {
        return DNS_TYPE_PTR;
    }
    if (type == "mx") {
        return DNS_TYPE_MX;
    }
    if (type == "txt") {
        return DNS_TYPE_TXT;
    }
    return 0;
}

} // namespace

void LocalRecords::Load(const std::vector<LocalRecord> &records) {
    records_.clear();
    for (size_t i = 0; i < records.size(); ++i) {
        const LocalRecord &rec = records[i];
        unsigned short qtype = TypeFromString(ToLower(rec.type));
        if (qtype == 0) {
            continue;
        }
        records_[MakeKey(rec.name, qtype)] = rec;
    }
}

bool LocalRecords::Resolve(const std::string &name, unsigned short qtype, std::string *value, unsigned short *rtype) const {
    std::map<std::string, LocalRecord>::const_iterator it = records_.find(MakeKey(name, qtype));
    if (it == records_.end()) {
        return false;
    }
    if (value) {
        *value = it->second.value;
    }
    if (rtype) {
        *rtype = qtype;
    }
    return true;
}

} // namespace gravastar
