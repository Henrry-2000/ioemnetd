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
        return NULL;
    }
    printf("UDP server is running...\n");
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
            ERROR_MESSAGE_T ret = BufferInQueue(buffer, n);
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