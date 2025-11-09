// tests/fw_stub.cpp
// Simple stub for execIptablesRestore used by tests.
// It records last target/command and returns next_ret (0 = success).
#include <string>
#include <mutex>

static std::string g_last_command;
static int g_last_target = -1;
static int g_next_ret = 0;
static std::mutex g_mtx;

void tests_reset_stub(int ret = 0) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_last_command.clear();
    g_last_target = -1;
    g_next_ret = ret;
}

std::string tests_last_command() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_last_command;
}
int tests_last_target() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_last_target;
}
void tests_set_next_ret(int r) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_next_ret = r;
}

// NOTE: the real execIptablesRestore signature in your code may be different.
// If so, adjust this function signature to match exactly (names/types).
// This stub must be linked instead of the real implementation.
int execIptablesRestore(int target, const char* command) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_last_target = target;
    g_last_command = command ? std::string(command) : std::string();
    return g_next_ret;
}
