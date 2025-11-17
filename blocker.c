// system/netd/ioemnetd/blocker.c
#include "blocker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

// We call into dns_client.c's search function to reuse ip2region logic.
// Declare it here as extern. dns_client.c already defines this function:
// int search_ip_string(char* ip, char* is_china);
extern int search_ip_string(char* ip, char* is_china);

/*
 * Note: we deliberately keep this module light-weight:
 * - blocker_is_ip_foreign uses search_ip_string() to check if ip is domestic.
 * - blocker_block_ip / unblock_ip are implemented as simple iptables command wrappers.
 *   These are optional / fallback and may require root/SELinux permissions.
 */

// Initialize blocker. No-op here; ip2region initialization is done by dns_client.
int blocker_init(void) {
    // If you want blocker to initialize ip2region itself, call ip2region_init() here,
    // but keep in mind ip2region_init() is in dns_client.c in current repo.
    return 0;
}

void blocker_shutdown(void) {
    // nothing to free for simple implementation
}

// Return 1 = foreign, 0 = domestic, -1 = error
int blocker_is_ip_foreign(const char* ip) {
    if (!ip) return -1;
    // search_ip_string expects char* for ip and writes a char result as is_china (1/0).
    char is_china = 0;
    // search_ip_string returns 0 on success, non-zero on failure per dns_client.c
    int rc = search_ip_string((char*)ip, &is_china);
    if (rc != 0) {
        // lookup failed -> treat as error (policy could treat as foreign)
        return -1;
    }
    if (is_china == 1) return 0; // domestic
    return 1; // foreign
}

// ipstrs: array of pointers (not modified). count: number of entries.
// Returns 1 if any ip is foreign, 0 if all domestic, -1 on error.
int blocker_should_block_by_iplist(const char** ipstrs, int count) {
    if (!ipstrs || count <= 0) return 0;
    for (int i = 0; i < count; ++i) {
        const char* ip = ipstrs[i];
        if (!ip) continue;
        int r = blocker_is_ip_foreign(ip);
        if (r == 1) return 1;    // found foreign
        if (r == -1) {
            // lookup failure -> conservative: treat as foreign (or change policy)
            return 1;
        }
    }
    return 0; // none foreign
}

// Helper to run iptables/ip6tables command with arguments (blocking).
// This is a simple wrapper: it forks and execvp the given argv list.
// Returns 0 on success (child exit status 0), -1 on internal error, or >0 child exit code.
static int run_cmd_wait(char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // child
        execvp(argv[0], argv);
        _exit(127);
    }
    // parent
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

// // Optional: simplistic iptables implementation (may require root)
// int blocker_block_ip(uid_t uid, const char* ip, int ttl_seconds) {
//     if (!ip) return -1;
//     char uidbuf[32];
//     snprintf(uidbuf, sizeof(uidbuf), "%u", (unsigned)uid);
//     // choose iptables vs ip6tables by presence of ':' in ip
//     int is_v6 = (strchr(ip, ':') != NULL);
//     // Build argv: iptables -I OUTPUT -m owner --uid-owner UID -d IP -j DROP
//     if (is_v6) {
//         char *argv[] = {"ip6tables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", uidbuf, "-d", (char*)ip, "-j", "DROP", NULL};
//         return run_cmd_wait(argv);
//     } else {
//         char *argv[] = {"iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", uidbuf, "-d", (char*)ip, "-j", "DROP", NULL};
//         return run_cmd_wait(argv);
//     }
// }

int blocker_unblock_ip(uid_t uid, const char* ip) {
    if (!ip) return -1;
    char uidbuf[32];
    snprintf(uidbuf, sizeof(uidbuf), "%u", (unsigned)uid);
    int is_v6 = (strchr(ip, ':') != NULL);
    if (is_v6) {
        char *argv[] = {"ip6tables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", uidbuf, "-d", (char*)ip, "-j", "DROP", NULL};
        return run_cmd_wait(argv);
    } else {
        char *argv[] = {"iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", uidbuf, "-d", (char*)ip, "-j", "DROP", NULL};
        return run_cmd_wait(argv);
    }
}