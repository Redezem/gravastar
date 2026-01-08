#include "cache.h"

#include <unistd.h>

bool TestCache() {
    gravastar::DnsCache cache(32, 1);
    std::vector<unsigned char> resp1(20, 0x01);
    std::vector<unsigned char> resp2(20, 0x02);

    cache.Put("a|1", resp1);
    cache.Put("b|1", resp2);

    std::vector<unsigned char> out;
    if (!cache.Get("b|1", &out)) {
        return false;
    }
    if (out.size() != resp2.size()) {
        return false;
    }

    usleep(1100000);
    if (cache.Get("a|1", &out)) {
        return false;
    }
    return true;
}
