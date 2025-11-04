/**
 * @file dns_client.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-07-24
 * 
 * @copyright Copyright (c) 2025
 * 
 */

#ifndef DNS_CLIENT_H
#define DNS_CLIENT_H
#ifdef __cplusplus
extern "C"
{
#endif
#include "queue.h"
#include "selog.h"

#define boolean unsigned char
int dns_client_init();
uint8 log_write(Selog_LogType type, uint16 eventid, uint16 user_eventid, Selog_LogLevelType level, boolean urgent_flag,
                const char *format, ...);
void set_db_path(char *new_db_path);
void set_region(char new_region);
void set_log_path(char *new_log_path);
void Stop_And_Exit(int signal);
void *udp_server_loop(void *arg);
void* main_loop(void *arg);
#ifdef __cplusplus
}
#endif
#endif