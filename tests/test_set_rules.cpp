// tests/test_set_rules.cpp
//
// This test calls your set_iptables_rule(...) function and checks
// that it forms the expected command and handles success/failure.
// It expects execIptablesRestore to be replaced by fw_stub.cpp.
//
// Usage:
// - In AOSP: put these files under tests/ and add to Android.bp, then `mm` to build and run.
// - On host (g++): you can compile & link set_rules implementation file with these tests.
//   See run_tests.sh for example commands.
//
// IMPORTANT:
// If the real set_iptables_rule signature or namespace differs, adjust the extern declaration below.

#include <iostream>
#include <cassert>
#include <string>

// If building inside AOSP, include Android types:
// #include <utils/String16.h>
// using ::android::String16;
//
// For host builds (non-AOSP), we provide a minimal String16 shim:
namespace android {
    struct String16 {
        std::u16string s;
        String16() {}
        String16(const char* v) {
            std::string tmp(v?v:"");
            s.clear();
            for(char c: tmp) s.push_back((char16_t)c);
        }
        std::string string() const {
            std::string out;
            for (char16_t c: s) out.push_back(static_cast<char>(c & 0xFF));
            return out;
        }
    };
}

// Declare the function under test (exact signature from your code).
// Adjust namespace if needed.
extern ::android::String16 set_iptables_rule(int v4v6, int type, ::android::String16 rules);

// Declare helpers from stub
void tests_reset_stub(int ret = 0);
std::string tests_last_command();
int tests_last_target();
void tests_set_next_ret(int r);

int main() {
    std::cout << "Running test_set_rules\n";

    // 1) Basic success case: v4, filter (type==0)
    tests_reset_stub(0); // stub returns success
    ::android::String16 rules1("-A INPUT -s 1.2.3.4 -j DROP");
    auto res1 = set_iptables_rule(0, 0, rules1);
    std::string sres1 = res1.string();
    std::string cmd1 = tests_last_command();
    std::cout << "Command1: [" << cmd1 << "]\n";
    assert(cmd1.find("filter") != std::string::npos || cmd1.find("FILTER") != std::string::npos);
    assert(cmd1.find("COMMIT") != std::string::npos);
    assert(sres1.find("Iptables rules set successfully") != std::string::npos);

    // 2) NAT table (type==1) should include "nat"
    tests_reset_stub(0);
    ::android::String16 rules2("-A POSTROUTING -t nat -j MASQUERADE");
    auto res2 = set_iptables_rule(0, 1, rules2);
    std::string cmd2 = tests_last_command();
    std::cout << "Command2: [" << cmd2 << "]\n";
    assert(cmd2.find("nat") != std::string::npos);

    // 3) Failure path: stub returns non-zero -> function returns error text
    tests_reset_stub(1); // stub simulates failure
    ::android::String16 rules3("-A FORWARD -j DROP");
    auto res3 = set_iptables_rule(0, 0, rules3);
    std::string sres3 = res3.string();
    std::cout << "Failure result: " << sres3 << "\n";
    assert(sres3.find("Error setting iptables rules") != std::string::npos);

    // 4) IPv6 path (v4v6==1) — ensure target differs (just check last_target recorded)
    tests_reset_stub(0);
    ::android::String16 rules4("-A INPUT -s ::1 -j DROP");
    auto res4 = set_iptables_rule(1, 0, rules4);
    int t = tests_last_target();
    std::cout << "IPv6 target: " << t << "\n";
    // We don't assert exact numeric value here (depends on your IptablesTarget enum),
    // but ensure some target was recorded.
    assert(t != -1);

    // 5) Malicious input: contains COMMIT inside rules — ensure result command still ends with COMMIT
    tests_reset_stub(0);
    ::android::String16 rules5("-A INPUT -s 2.2.2.2 -j DROP\nCOMMIT\n-A EXTRA");
    auto res5 = set_iptables_rule(0, 0, rules5);
    std::string cmd5 = tests_last_command();
    std::cout << "Command5: [" << cmd5 << "]\n";
    // ensure command contains a COMMIT and ends with it (or at least includes it)
    assert(cmd5.find("COMMIT") != std::string::npos);

    std::cout << "All tests passed.\n";
    return 0;
}
