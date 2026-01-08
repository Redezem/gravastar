#ifndef GRAVASTAR_BLOCKLIST_H
#define GRAVASTAR_BLOCKLIST_H

#include <set>
#include <string>

namespace gravastar {

class Blocklist {
public:
    Blocklist();
    void SetDomains(const std::set<std::string> &domains);
    bool IsBlocked(const std::string &name) const;

private:
    std::set<std::string> domains_;
};

} // namespace gravastar

#endif // GRAVASTAR_BLOCKLIST_H
