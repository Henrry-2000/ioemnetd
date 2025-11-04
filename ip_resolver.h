/**
 * @file ip_resolver.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-07-15
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#ifndef IP_RESOLVER_H
#define IP_RESOLVER_H



void InitializeRegex();
void destroy_regex();
void found_ip_addresses(const char *subject, int *match_count, char *match_results[]);




#endif // IP_RESOLVER_H