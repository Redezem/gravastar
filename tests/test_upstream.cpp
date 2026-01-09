#include "upstream_resolver.h"

#include <string>

bool TestParseHostPort() {
    std::string host;
    int port = 0;
    if (!gravastar::ParseHostPort("dns.example", 853, &host, &port)) {
        return false;
    }
    if (host != "dns.example" || port != 853) {
        return false;
    }
    if (!gravastar::ParseHostPort("dns.example:8853", 853, &host, &port)) {
        return false;
    }
    if (host != "dns.example" || port != 8853) {
        return false;
    }
    if (!gravastar::ParseHostPort("[2001:db8::1]:853", 853, &host, &port)) {
        return false;
    }
    if (host != "2001:db8::1" || port != 853) {
        return false;
    }
    if (gravastar::ParseHostPort("", 853, &host, &port)) {
        return false;
    }
    if (gravastar::ParseHostPort(":853", 853, &host, &port)) {
        return false;
    }
    if (gravastar::ParseHostPort("dns.example:abc", 853, &host, &port)) {
        return false;
    }
    if (gravastar::ParseHostPort("[2001:db8::1", 853, &host, &port)) {
        return false;
    }
    if (gravastar::ParseHostPort("dns.example:", 853, &host, &port)) {
        return false;
    }
    return true;
}
