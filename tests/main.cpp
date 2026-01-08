#include <iostream>

bool TestCache();
bool TestConfig();
bool TestDnsPacket();

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
    if (failures == 0) {
        std::cout << "All tests passed\n";
        return 0;
    }
    return 1;
}
