// system/netd/ioemnetd/blocker.h
#ifndef IOEMNETD_BLOCKER_H
#define IOEMNETD_BLOCKER_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initialize blocker (optional). Returns 0 on success.
int blocker_init(void);

// Shutdown/cleanup.
void blocker_shutdown(void);

// Return 1 if ip is foreign (non-China), 0 if domestic (China), -1 on error.
int blocker_is_ip_foreign(const char* ip);

// Given a list of ip strings, return 1 if any ip is foreign, 0 if all domestic,
// -1 if error. ipstrs pointer may be NULL-terminated or pass count explicitly.
int blocker_should_block_by_iplist(const char** ipstrs, int count);

// Optional: add iptables block for (uid, ip) with TTL seconds. Return 0 on success.
// int blocker_block_ip(uid_t uid, const char* ip, int ttl_seconds);

// Optional: remove iptables block for (uid, ip). Return 0 on success.
int blocker_unblock_ip(uid_t uid, const char* ip);

#ifdef __cplusplus
}
#endif
#endif // IOEMNETD_BLOCKER_H