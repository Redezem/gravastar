#ifndef GRAVASTAR_BLOCKLIST_H
#define GRAVASTAR_BLOCKLIST_H

#include <set>
#include <string>
#include <pthread.h>

namespace gravastar {

class Blocklist {
public:
    Blocklist();
    ~Blocklist();
    void SetDomains(const std::set<std::string> &domains);
    bool IsBlocked(const std::string &name) const;

private:
    Blocklist(const Blocklist &);
    Blocklist &operator=(const Blocklist &);

    std::set<std::string> domains_;
    mutable pthread_rwlock_t lock_;
};

} // namespace gravastar

#endif // GRAVASTAR_BLOCKLIST_H
