#include "upstream_resolver.h"
#include "util.h"

#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <vector>

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

bool TestLogFieldSanitize() {
    // Newlines, spaces and control characters in client-controlled fields
    // must not survive into the space-separated key=value log format.
    std::string dirty = std::string("evil\nqname=injected x\x01y\x7f");
    std::string clean = gravastar::SanitizeLogField(dirty);
    if (clean.find('\n') != std::string::npos) {
        return false;
    }
    if (clean.find(' ') != std::string::npos) {
        return false;
    }
    if (clean.find('\x01') != std::string::npos || clean.find('\x7f') != std::string::npos) {
        return false;
    }
    if (clean != "evil_qname=injected_x_y_") {
        return false;
    }
    // Ordinary values pass through untouched.
    if (gravastar::SanitizeLogField("host.example.com") != "host.example.com") {
        return false;
    }
    return true;
}

bool TestClientAcl() {
    struct sockaddr_in client;
    std::memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;

    std::vector<std::string> empty;
    inet_pton(AF_INET, "8.8.8.8", &client.sin_addr);
    if (!gravastar::ClientAllowed(client, empty)) {
        return false;
    }

    std::vector<std::string> acl;
    acl.push_back("10.1.0.0/16");
    acl.push_back("192.168.1.5");
    inet_pton(AF_INET, "10.1.2.3", &client.sin_addr);
    if (!gravastar::ClientAllowed(client, acl)) {
        return false;
    }
    inet_pton(AF_INET, "10.2.2.3", &client.sin_addr);
    if (gravastar::ClientAllowed(client, acl)) {
        return false;
    }
    inet_pton(AF_INET, "192.168.1.5", &client.sin_addr);
    if (!gravastar::ClientAllowed(client, acl)) {
        return false;
    }
    inet_pton(AF_INET, "192.168.1.6", &client.sin_addr);
    if (gravastar::ClientAllowed(client, acl)) {
        return false;
    }
    // Garbage entries never match; a lone garbage list denies everything.
    std::vector<std::string> junk;
    junk.push_back("banana");
    junk.push_back("10.0.0.0/33");
    inet_pton(AF_INET, "10.1.2.3", &client.sin_addr);
    if (gravastar::ClientAllowed(client, junk)) {
        return false;
    }
    return true;
}
