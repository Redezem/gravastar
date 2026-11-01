#include <iostream>

bool TestCache();
bool TestConfig();
bool TestDnsPacket();
bool TestDnsRebindRanges();
bool TestDnsResponseValidation();
bool TestDnsMinTtl();
bool TestLoggingRotation();
bool TestLoggingFailurePath();
bool TestControllerLoggerRotation();
bool TestControllerLogLevelFilter();
bool TestParseHostPort();
bool TestLogFieldSanitize();
bool TestClientAcl();
bool TestUpstreamBlocklistParse();
bool TestUpstreamBlocklistCacheFallback();

int main() {
    int failures = 0;
    if (!TestCache()) {
        std::cerr << "TestCache failed\n";
        failures++;
    }
    if (!TestConfig()) {
        std::cerr << "TestConfig failed\n";
        failures++;
    }
    if (!TestDnsPacket()) {
        std::cerr << "TestDnsPacket failed\n";
        failures++;
    }
    if (!TestDnsRebindRanges()) {
        std::cerr << "TestDnsRebindRanges failed\n";
        failures++;
    }
    if (!TestDnsResponseValidation()) {
        std::cerr << "TestDnsResponseValidation failed\n";
        failures++;
    }
    if (!TestDnsMinTtl()) {
        std::cerr << "TestDnsMinTtl failed\n";
        failures++;
    }
    if (!TestLoggingRotation()) {
        std::cerr << "TestLoggingRotation failed\n";
        failures++;
    }
    if (!TestLoggingFailurePath()) {
        std::cerr << "TestLoggingFailurePath failed\n";
        failures++;
    }
    if (!TestControllerLoggerRotation()) {
        std::cerr << "TestControllerLoggerRotation failed\n";
        failures++;
    }
    if (!TestControllerLogLevelFilter()) {
        std::cerr << "TestControllerLogLevelFilter failed\n";
        failures++;
    }
    if (!TestParseHostPort()) {
        std::cerr << "TestParseHostPort failed\n";
        failures++;
    }
    if (!TestLogFieldSanitize()) {
        std::cerr << "TestLogFieldSanitize failed\n";
        failures++;
    }
    if (!TestClientAcl()) {
        std::cerr << "TestClientAcl failed\n";
        failures++;
    }
    if (!TestUpstreamBlocklistParse()) {
        std::cerr << "TestUpstreamBlocklistParse failed\n";
        failures++;
    }
    if (!TestUpstreamBlocklistCacheFallback()) {
        std::cerr << "TestUpstreamBlocklistCacheFallback failed\n";
        failures++;
    }
    if (failures == 0) {
        std::cout << "All tests passed\n";
        return 0;
    }
    return 1;
}
