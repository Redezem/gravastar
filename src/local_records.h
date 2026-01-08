#ifndef GRAVASTAR_LOCAL_RECORDS_H
#define GRAVASTAR_LOCAL_RECORDS_H

#include <map>
#include <string>
#include <vector>

#include "config.h"

namespace gravastar {

class LocalRecords {
public:
    void Load(const std::vector<LocalRecord> &records);
    bool Resolve(const std::string &name, unsigned short qtype, std::string *value, unsigned short *rtype) const;

private:
    std::map<std::string, LocalRecord> records_;
};

} // namespace gravastar

#endif // GRAVASTAR_LOCAL_RECORDS_H
