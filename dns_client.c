/* PATCH START: add blocker include, global udp fd, and send_dns_refused */
#include "blocker.h"   // new
#include <log/log.h>

static int g_udp_sockfd = -1; // set by udp_server_loop so main_loop can reply

// Helper: send DNS REFUSED (RCODE=5) back to UDP client using same socket fd.
// reqbuf: original request bytes, reqlen: length, cli: client addr, cli_len: len.
static void send_dns_refused(int sockfd, const unsigned char *reqbuf, size_t reqlen,
                             const struct sockaddr *cli, socklen_t cli_len, int rcode)
{
    if (!reqbuf || reqlen < 12 || sockfd < 0 || !cli) return;

    // Copy header and question section, but set QR bit, set RCODE,
    // zero ANCOUNT/NS/ARCOUNT. Keep question as-is.
    // We will return the same number of bytes as request (header + question).
    // Note: this assumes reqbuf contains the entire DNS query (header + question).
    // If the request uses extensions/EDNS larger than our buffer, adapt accordingly.

    unsigned char resp[2048];
    size_t resp_len = reqlen;
    if (resp_len > sizeof(resp)) resp_len = sizeof(resp);
    memcpy(resp, reqbuf, resp_len);

    // flags are at offset 2 (network order)
    uint16_t flags_net;
    memcpy(&flags_net, resp + 2, sizeof(flags_net));
    uint16_t flags = ntohs(flags_net);

    // set QR (response) bit
    flags |= 0x8000;
    // clear low 4 bits (rcode) and set given rcode
    flags = (flags & 0xFFF0) | (rcode & 0xF);

    uint16_t newflags_net = htons(flags);
    memcpy(resp + 2, &newflags_net, sizeof(newflags_net));

    // zero ANCOUNT, NSCOUNT, ARCOUNT
    uint16_t zero = htons(0);
    memcpy(resp + 6, &zero, sizeof(zero)); // ANCOUNT
    memcpy(resp + 8, &zero, sizeof(zero)); // NSCOUNT
    memcpy(resp + 10, &zero, sizeof(zero)); // ARCOUNT

    // sendto client
    ssize_t w = sendto(sockfd, resp, resp_len, 0, cli, cli_len);
    if (w < 0) {
        ALOGE("send_dns_refused sendto failed: %s", strerror(errno));
    } else {
        ALOGI("send_dns_refused: sent %zd bytes rcode=%d to client", w, rcode);
    }
}
/* PATCH END */

/**
 * @file dns_client.c
 * @author fujy (fujy@vecentek.com)
 * @brief
 * @version 0.1
 * @date 2025-07-15
 *
 * @copyright Copyright (c) 2025
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <pcre2.h>
#include "xdb_searcher.h"
#include "queue.h"
#include "ip_resolver.h"
#include "cJSON.h"
#include "selog.h"
#include "dns_client.h"
#include <signal.h>

#define MAX_LEN 1024
#define MAX_PCK 1000 // 最大包数
#define LISTEN_IP "127.0.0.1"
#define LISTEN_PORT 19330 // 监听端口
#define MAIN_FUNC_CYCLE 10*1000 // 主循环周期，单位毫秒
#define FOREIGN 1 
#define DOMESTIC 0 
#define LOG_PATH "/data/system/dns_client" // 日志路径


// 示例消息 DnsRet:success,domain:域名,UID:UID,PID:pid;114.114.114.114,8.8.8.8,1.1.1.1;

static char *db_path = "/system/etc/ip2region.xdb"; // 数据库路径
static char* log_path = LOG_PATH; // 日志路径
static xdb_vector_index_t *v_index;
static xdb_searcher_t searcher;
static selog_handle hselog = NULL;
static char region = DOMESTIC;
/**
 * @brief 初始化队列
 * 
 */
void Queue_Init(void)
{
    ERROR_MESSAGE_T ret = QueueInit();
    if (ret != SUCCESS)
    {
        printf("Queue initialization failed with error code: %d\n", ret);
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief  日志库方式初始化
 * @param  log_path         日志路径
 * @return int
 */
int log_init(const char *log_path)
{
    if (log_path == NULL)
    {
        return -1;
    }
    Selog_CreateHandle(&hselog, SELOG_MODEL_CLIENT, "ioemnetd");
    Selog_SetConfCommon(hselog, SELOG_CFG_CAPACITY, 1024 * 1024);
    Selog_SetConfCommon(hselog, SELOG_CFG_PATH, log_path);
    Selog_Init(hselog);
    printf("Log initialized successfully with path: %s\n", log_path);
    if (hselog != 0)
        return 0;

    return -1;
}

void log_deinit()
{
    if (hselog != NULL)
    {
        Selog_Deinit(hselog);
        hselog = NULL;
    }
}

uint8 log_write(Selog_LogType type, uint16 eventid, uint16 user_eventid, Selog_LogLevelType level, boolean urgent_flag,
                const char *format, ...)
{
    uint8 ret = 0;
    Selog_WriteStructType w_st;
    va_list ap;
    char logbuf[SELOG_SINGLE_LOG_SIZE] = {0};
    uint32 log_len;

    memset(&w_st, 0, sizeof(Selog_WriteStructType));

    va_start(ap, format);
    vsnprintf(logbuf, SELOG_SINGLE_LOG_SIZE, format, ap);
    va_end(ap);
    logbuf[SELOG_SINGLE_LOG_SIZE - 1] = '\0';
    log_len = strlen(logbuf);

    w_st.log_type = type;
    w_st.eventid = eventid;
    w_st.user_eventid = user_eventid;
    w_st.level = level;
    w_st.urgent_flag = urgent_flag;
    w_st.aggregation_count = 0;
    memset(w_st.app_tags, 0, sizeof(w_st.app_tags));
    strncpy(w_st.app_tags, "dns_client", SELOG_APP_TAGS_SIZE);
    ret = Selog_Write(hselog, w_st, logbuf, log_len);
    if (ret != 0) {
        printf("Failed to write log: %s, error code: %d\n", logbuf, ret);
    } else {
        printf("Log written successfully: %s\n", logbuf);
    }

    return ret;
}

/**
 * @brief udp服务器循环函数
 * 
 * @param arg 
 * @return void* 
 */
void *udp_server_loop(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());   // 设置线程为分离状态
    prctl(PR_SET_NAME, "Udp_Server"); // 设置线程名称为Udp_Server
    int server_fd;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(LISTEN_IP);
    server_addr.sin_port = htons(LISTEN_PORT);
    struct sockaddr_in client_addr;
    uint8_t buffer[MAX_LEN] = {0};
    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0)
    {
        printf("socket error: %s(errno: %d)\n", strerror(errno), errno);
        return NULL;
    }
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("bind error: %s(errno: %d)\n", strerror(errno), errno);
        close(server_fd);
        return NULL;
    }
    printf("UDP server is running...\n");
    /* PATCH START: store server sockfd so worker can reply */
    // existing code creates 'server_fd' prior to loop
    g_udp_sockfd = server_fd; // save for main_loop replies
    /* PATCH END */
    while (1)
    {
        socklen_t len = sizeof(client_addr);
        int n = recvfrom(server_fd, buffer, MAX_LEN, 0, (struct sockaddr *)&client_addr, &len);
        if (n < 0)
        {
            printf("recvfrom error: %s(errno: %d)\n", strerror(errno), errno);
            break;
        }
        buffer[n] = '\0'; // 确保字符串以null结尾
        printf("Received data: %s\n", buffer);
        if (GetQueueSize() > MAX_PCK)
        {
            printf("Queue is full, dropping packet\n");
            continue; // 队列已满，丢弃数据包
        }
        else
        {
            ERROR_MESSAGE_T ret = BufferInQueue(buffer, n, (struct sockaddr *)&client_addr, len);
            if (ret != SUCCESS)
            {
                printf("Failed to enqueue data with error code: %d\n", ret);
            }
            else
            {
                printf("Data enqueued successfully, current queue size: %d\n", GetQueueSize());
            }
        }
        usleep(MAIN_FUNC_CYCLE);
    }
    close(server_fd);
    g_udp_sockfd = -1; 
    printf("UDP server stopped.\n");
    return NULL;
}

/**
 * @brief Get the pid name object 
 * @note if return NULL, means the pid is not exist or error,else return the process name. ptr need to be freed by caller.
 * @param pid 
 * @return char* 
 */
char *get_pid_name(int pid)
{
    FILE *fp = NULL;
    char pid_path[64] = {0};
    snprintf(pid_path, sizeof(pid_path), "/proc/%d/cmdline", pid);
    fp = fopen(pid_path, "r");
    if (fp == NULL)
    {
        printf("Failed to open file %s: %s\n", pid_path, strerror(errno));
        return NULL;
    }
    char *pid_name = (char *)malloc(256);
    if (pid_name == NULL)
    {
        printf("Memory allocation failed\n");
        fclose(fp);
        return NULL;
    }
    size_t n = fread(pid_name, 1, 255, fp);
    if (n < 1)
    {
        printf("Failed to read from file %s: %s\n", pid_path, strerror(errno));
        free(pid_name);
        fclose(fp);
        return NULL;
    }
    pid_name[n] = '\0'; // 确保字符串以null结尾
    fclose(fp);
    return pid_name;
}

/**
 * @brief 解析消息
 * 
 * @param message 
 * @param dnsRet 
 * @param domain 
 * @param uid 
 * @param pid 
 * @return int 
 */
int PraseMessage(const char *message, char *dnsRet, char *domain, int *uid, int *pid)
{
    // 使用sscanf提取内容，忽略分号后面的IP部分
    int result = sscanf(message, 
                       "DnsRet:%[^,],domain:%[^,],UID:%d,PID:%d;",
                       dnsRet, domain, uid, pid);
    int ret = 0;
    if (result != 4)
    {
        printf("Failed to parse message: %s ret is %d\n", message,result);
        ret =  1; // 返回-1表示解析失败
    }
    else
    {
        printf("DnsRet: %s, Domain: %s, UID: %d, PID: %d\n", dnsRet, domain, *uid, *pid);
    }
    return ret; // 返回0表示解析成功
}

/**
 * @brief ip2region初始化函数
 * 
 * @return int 
 */
int ip2region_init()
{
    // 初始化ip2region
    v_index = xdb_load_vector_index_from_file(db_path);
    if (v_index == NULL) {
        printf("failed to load vector index from `%s`\n", db_path);
        return 1;
    }

    // 2、使用全局的 VectorIndex 变量创建带 VectorIndex 缓存的 xdb 查询对象
    int err = xdb_new_with_vector_index(&searcher, db_path, v_index);
    if (err != 0) {
        printf("failed to create vector index cached searcher with errcode=%d\n", err);
        return 2;
    }
    printf("ip2region initialized successfully with database: %s\n", db_path);
    return 0; // 返回0表示初始化成功
}

/**
 * @brief  释放ip2region资源
 * 
 */
void ip2region_deinit()
{
    xdb_close(&searcher);
    xdb_close_vector_index(v_index);
}

/**
 * @brief 通过ip字符串查询IP归属地(是否为中国IP)

 * @param ip char* IP地址字符串
 * @param is_china char* 返回值指针，设置为1表示是中国IP，0表示不是中国IP
 * @return int 
 */
int search_ip_string(char* ip,char* is_china)
{
    long s_time;
    char region_buffer[256] = {0};
    s_time = xdb_now();
    int err = xdb_search_by_string(&searcher, ip, region_buffer, sizeof(region_buffer));
    if(err != 0)
    {
        printf("failed to search ip `%s` with errcode=%d\n", ip, err);
        return 1; // 返回1表示查询失败
    }
    else
    {
        printf("ip: %s, region: %s, cost: %ld μs\n", ip, region_buffer, xdb_now() - s_time);
        // 检查是否为中国IP
        if (strstr(region_buffer, "中国") != NULL)
        {
            *is_china = 1; // 设置为1表示是中国IP
        }
        else
        {
            *is_china = 0; // 设置为0表示不是中国IP
        }
    }
    return 0; // 返回0表示查询成功
}

// Returns: 1 if China/domestic, 0 if foreign, -1 on error
int is_china_ip(const char* ip) {
    if (!ip) return -1;
    char is_china = 0;
    // search_ip_string expects char* ip and char* is_china
    int rc = search_ip_string((char*)ip, &is_china);
    if (rc != 0) return -1; // lookup failed
    return (is_china == 1) ? 1 : 0;
}

/**
 * @brief 处理数据的循环
 * 
 * @param arg 
 */
void* main_loop(void *arg)
{
    (void)arg;
    pthread_detach(pthread_self());   // 设置线程为分离状态
    prctl(PR_SET_NAME, "Main_Loop"); // 设置线程名称为Main_Loop
    while (1)
    {
        struct List_Node *node = NULL;
        ERROR_MESSAGE_T ret = BufferOutQueue(&node);
        if (ret == BUF_EMPTY)
        {
            usleep(MAIN_FUNC_CYCLE); // 队列为空，等待100毫秒
            continue;
        }
        else if (ret != SUCCESS)
        {
            printf("Failed to dequeue data with error code: %d\n", ret);
            continue;
        }
        printf("Dequeued data: %s\n", node->data);
        // 处理数据
        char dnsRet[64] = {0};
        char domain[128] = {0};
        int uid = 0;
        int pid = 0;
        if(0 == PraseMessage((const char *)node->data, dnsRet, domain, &uid, &pid))
        {
            // 获取进程名称 
            char *pid_name = get_pid_name(pid);
            printf("Process name for PID %d: %s\n", pid, pid_name ? pid_name : "Unknown");
            // 提取IP
            int match_count = 0;
            char *match_results[32] = {0};
            found_ip_addresses((const char *)node->data, &match_count, match_results);
            printf("Found %d IP addresses:\n", match_count);
            uint8 found_addr_count = 0;
            uint8 found_index_array[32] = {0}; // 用于记录找到的IP地址索引
            // 查询归属地
            for (int i = 0; i < match_count; i++)
            {
                printf("IP %d: %s\n", i + 1, match_results[i]);
                char is_china = 0;
                if( 0 == search_ip_string(match_results[i], &is_china))
                {
                    if(is_china)
                    {
                        printf("IP %s is a China IP\n", match_results[i]);
                        if(region == FOREIGN)
                        {
                            found_index_array[found_addr_count] = i; // 记录找到的IP地址索引
                            found_addr_count++; 
                        }   
                    }
                    else
                    {
                        printf("IP %s is not a China IP\n", match_results[i]);
                        if(region != DOMESTIC)
                        {
                            printf("Skipping foreign IP %s as region is set to foreign\n", match_results[i]);
                            // blocker_block_ip(uid, match_results[i], 3600);
                        }
                        else
                        {
                            printf("IP %s is a domestic IP\n", match_results[i]);
                            found_index_array[found_addr_count] = i; // 记录找到的IP地址索引
                            found_addr_count++;
                        }
                    }
                }
                else
                {
                    found_index_array[found_addr_count] = i; // 记录找到的IP地址索引
                    found_addr_count++; 
                    printf("Failed to search IP %s\n", match_results[i]);
                }
            }
            /* --- BEGIN: DNS-layer immediate refusal for foreign IPs --- */
            int foreign_found = 0;
            for (int i = 0; i < match_count; i++) {
                if (match_results[i] == NULL) continue;
                int is_foreign = blocker_is_ip_foreign(match_results[i]);
                if (is_foreign == 1) {
                    foreign_found = 1;
                    // if you want to log which IP triggered block:
                    printf("Blocking domain %s due to foreign IP %s\n", domain, match_results[i]);
                    break;
                } else if (is_foreign == -1) {
                    // lookup error: conservative policy -> treat as foreign
                    foreign_found = 1;
                    printf("IP lookup error for %s, treating as foreign (conservative)\n", match_results[i]);
                    break;
                }
            }

            if (foreign_found) {
                // Send DNS REFUSED response to client and skip normal processing.
                if (g_udp_sockfd >= 0 && node->addr_len > 0) {
                    struct sockaddr_in addr;
                    memcpy(&addr, &node->addr, sizeof(addr));
                    send_dns_refused(g_udp_sockfd,
                                     (const unsigned char*)node->data,
                                     node->len,
                                     (struct sockaddr *)&addr,
                                     node->addr_len,
                                     5); // REFUSED
                    printf("Sent DNS REFUSED for domain %s to client\n", domain);
                } else {
                    printf("Cannot send DNS REFUSED: no udp sockfd or missing addr\n");
                }

                // Cleanup: free pid_name and match_results entries, then free node and continue
                if (pid_name != NULL) {
                    free(pid_name);
                    pid_name = NULL;
                }
                for (int i = 0; i < match_count; i++) {
                    if (match_results[i]) {
                        free(match_results[i]);
                        match_results[i] = NULL;
                    }
                }
                // free the node memory (use your project's macro if exists)
                free(node);
                usleep(MAIN_FUNC_CYCLE);
                continue; // go to next packet
            }
            /* --- END: DNS-layer immediate refusal for foreign IPs --- */
            // 记录事件
            if(found_addr_count > 0)
            {
                printf("Found %d IP addresses matching the criteria:\n", found_addr_count);
                cJSON* event = cJSON_CreateObject();
                cJSON_AddStringToObject(event, "DnsRet", dnsRet);
                cJSON_AddStringToObject(event, "Domain", domain);
                cJSON_AddNumberToObject(event, "UID", uid);
                cJSON_AddNumberToObject(event, "PID", pid);
                cJSON_AddStringToObject(event, "ProcessName", pid_name ? pid_name : "Unknown");
                cJSON* ip_array = cJSON_CreateArray();
                for (int i = 0; i < found_addr_count; i++)
                {
                    int index = found_index_array[i];
                    cJSON_AddItemToArray(ip_array, cJSON_CreateString(match_results[index]));
                }
                cJSON_AddItemToObject(event, "IPAddresses", ip_array);
                char *event_str = cJSON_Print(event);
                if (event_str)
                {
                    printf("Event JSON: %s\n", event_str);
                    log_write(SELOG_LOG_TYPE_SYSTEM, 1, 1, SELOG_LOG_LEVEL_MIDDLE, FALSE,
                                "Event logged: %s", event_str); // 写入日志
                    free(event_str); // 释放JSON字符串内存
                }
                else
                {
                    printf("Failed to create JSON string for event\n");
                }
            }
            else
            {
                printf("No IP addresses matching the criteria were found\n");
            }
            if (pid_name != NULL)
            {
                free(pid_name); // 释放进程名称的内存
            }
            // 释放匹配结果的内存
            for (int i = 0; i < match_count; i++)
            {
                free(match_results[i]); // 释放每个匹配结果的内存
            }
        }
        free(node); // 释放节点内存
        usleep(MAIN_FUNC_CYCLE); 
    }
    return NULL;
}

/**
 * @brief 信号处理函数
 * 
 * @param signal 
 */
void Stop_And_Exit(int signal)
{
    printf("Received signal %d, stopping threads and exiting...\n", signal);
    ip2region_deinit(); // 释放ip2region资源
    destroy_regex(); // 销毁正则表达式匹配器
    bufferDestroy(); // 销毁队列
    log_deinit(); // 释放日志资源
    exit(0); // 退出程序
}

void set_region(char new_region)
{
    region = new_region; // 设置新的区域
    printf("Region set to: %s\n", (region == DOMESTIC) ? "Domestic" : "Foreign");
}

void set_db_path(char *new_db_path)
{
    if (new_db_path == NULL || strlen(new_db_path) == 0)
    {
        printf("Invalid database path\n");
        return;
    }
    db_path = new_db_path; // 设置新的数据库路径
    printf("Database path set to: %s\n", db_path);
}

void set_log_path(char *new_log_path)
{
    if (new_log_path == NULL || strlen(new_log_path) == 0)
    {
        printf("Invalid log path\n");
        return;
    }
    log_path = new_log_path; // 设置新的日志路径
    printf("Log path set to: %s\n", log_path);
}

int dns_client_init()
{
    // 初始化正则表达式匹配器
    InitializeRegex();
    // 初始化队列
    Queue_Init();
    // 初始化ip2region
    if (ip2region_init() != 0) {
        printf("Failed to initialize ip2region\n");
        return 1; // 初始化失败
    }
    // 初始化日志库
    if (log_init(log_path) != 0) {
        printf("Failed to initialize log library\n");
        return 2; // 日志库初始化失败
    }
    return 0; // 成功
}



#if 0
/**
 * @brief 主函数
 * 
 * @return int 
 */
int main()
{
    InitializeRegex(); // 初始化正则表达式匹配器
    Queue_Init(); // 初始化队列
    if (ip2region_init() != 0) {
        printf("Failed to initialize ip2region\n");
        return 1; // 初始化失败
    }
    log_init(LOG_PATH); // 初始化日志库
    // 注册信号处理函数
    signal(SIGINT, Stop_And_Exit); // Ctrl+C
    signal(SIGTERM, Stop_And_Exit); // kill命令
    pthread_t udp_thread, main_thread;
    // 创建UDP服务器线程
    if (pthread_create(&udp_thread, NULL, udp_server_loop, NULL) != 0)
    {
        printf("Failed to create UDP server thread\n");
        return 1; // 创建线程失败
    }
    // 创建主循环线程
    if (pthread_create(&main_thread, NULL, main_loop, NULL) != 0)
    {
        printf("Failed to create main loop thread\n");
        return 1; // 创建线程失败
    }
    while (1)
    {
        sleep(3);
    }
    
    return 0;
}
#endif