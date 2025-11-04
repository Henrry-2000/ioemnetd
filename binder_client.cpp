/**
 * @file binder_client.cpp
 * @brief
 * @author fujy (fujy@vecentek.com)
 * @version 1.0
 * @date 2025-07-04
 *
 * @copyright Copyright (c) 2025  vecentek
 *
 * @par 修改日志:
 * <table>
 * <tr><th>Date       <th>Version <th>Author  <th>Description
 * <tr><td>2025-07-04 <td>1.0     <td>fujy     <td>内容
 * </table>
 */

#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <regex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

#include <android-base/file.h>
#include <android-base/format.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android/multinetwork.h>
#include <binder/IPCThreadState.h>
#include <com/android/internal/net/BnOemNetdUnsolicitedEventListener.h>
#include <com/android/internal/net/IOemNetd.h>
#include "android/net/INetd.h"
#include "binder/IServiceManager.h"

#include "selog.h"
#include "dns_client.h"
#define LOG_PATH "/data/system/oemnetd_firewall/"

namespace binder = android::binder;

using android::IBinder;
using android::IServiceManager;
using android::sp;
using android::String16;
using android::String8;
using android::base::Join;
using android::base::make_scope_guard;
using android::base::ReadFdToString;
using android::base::ReadFileToString;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Trim;
using android::base::unique_fd;
using android::net::INetd;

sp<INetd> mNetd;
sp<com::android::internal::net::IOemNetd> oemNetd;
static char* config_path;
static char* log_path;
static char* db_path;
static char region;

#define uint8 unsigned char
#define uint16 unsigned short
#define uint32 unsigned int
#define boolean unsigned char

int NetdBinderInit() {
    int ret = 0;
    sp<IServiceManager> sm = android::defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("netd"));
    if (binder != nullptr) {
        mNetd = android::interface_cast<INetd>(binder);
    }
    if (mNetd == nullptr) {
        std::cerr << "Failed to get netd service" << std::endl;
        ret = -1;
    } else {
        std::cout << "Successfully connected to netd service" << std::endl;
        binder::Status status = mNetd->getOemNetd(&binder);
        if (!status.isOk()) {
            std::cerr << "Failed to get oem netd service: " << status.toString8().c_str()
                      << std::endl;
            ret = -1;
        } else {
            oemNetd = android::interface_cast<com::android::internal::net::IOemNetd>(binder);
            if (oemNetd == nullptr) {
                std::cerr << "Failed to cast to IOemNetd" << std::endl;
                ret = -1;
            } else {
                std::cout << "Successfully connected to oem netd service" << std::endl;
            }
        }
    }
    return ret;
}


void read_file_line(const char* path) {
    FILE* fp = fopen(path, "r");
    if (fp == nullptr) {
        std::cerr << "Failed to open file: " << path << ", error: " << strerror(errno) << std::endl;
        log_write(SELOG_LOG_TYPE_SYSTEM, 1, 1, SELOG_LOG_LEVEL_HIGH, false,
                  "Failed to open file: %s, error: %s ", path, strerror(errno));
        return;
    }
    int type = 0;
    char line[1024] = {0};
    while (fgets(line, sizeof(line), fp) != nullptr) {
        // Remove newline character
        std::cout << "Read line: " << line << std::endl;
        if (strstr(line, "mangle") != nullptr) {
            type = 2;  // Mangle
            std::cout << "Found mangle type, setting type to 2" << std::endl;
            memset(line, 0, sizeof(line));  // Clear the line buffer
            continue;                       // Skip
        } else if (strstr(line, "filter") != nullptr) {
            type = 0;  // Filter
            std::cout << "Found filter type, setting type to 0" << std::endl;
            memset(line, 0, sizeof(line));  // Clear the line buffer
            continue;                       // Skip
        } else if (strstr(line, "nat") != nullptr) {
            type = 1;  // Nat
            std::cout << "Found nat type, setting type to 1" << std::endl;
            memset(line, 0, sizeof(line));  // Clear the line buffer
            continue;                       // Skip
        }

        line[strlen(line) - 1] = '\0';  // Remove newline character
        line[strlen(line)] = '\0';
        char tmp[1024] = {0};
        memcpy(tmp, line, strlen(line) - 1);
        String16 rules = String16(tmp);
        std::cout << "Processed line: " << tmp << std::endl;
        std::cout << "#Setting iptables rules for type: " << type << ", rules: " << rules << "#"
                  << std::endl;
        // 判断加载结果 失败至多重试三次
        int retryCount = 0;
        bool success = false;
        do {
            String16* res = new String16();
            oemNetd->set_iptables_rules(0, type, rules, res);
            memset(line, 0, sizeof(line));  // Clear the line buffer
            std::cout << "Iptables rule set: " << *res << std::endl;
            String8 resStr = String8(*res);
            std::string resStrC = resStr.string();
            if(strstr(tmp,"-D") == NULL)  // 忽略 -D 操作
            {
                if (resStrC.find("ERROR") != std::string::npos) {
                    std::cerr << "Failed to set iptables rule: " << resStrC << std::endl;
                    success = false;
                    std::cerr << "After 1 s for retrying to set iptables rule... current count is " << retryCount << std::endl;
                    retryCount++;
                    sleep(1);
                    if(retryCount == 3)
                    {
                        //记录加载失败的日志
                        log_write(SELOG_LOG_TYPE_SYSTEM, 1, 1, SELOG_LOG_LEVEL_HIGH, false, "rules:%s Failed Reason:%s",tmp,resStrC.c_str());
                    }
                }else
                {
                    success = true;
                }
            }else
            {
                success = true;  // -D 操作不需要验证成功
            }
            delete res;
        } while (success == false && retryCount++ < 3);

        usleep(10 * 1000);  // Sleep for 10ms to avoid overwhelming the service
    }
    if (ferror(fp)) {
        std::cerr << "Error reading file: " << path << ", error: " << strerror(errno) << std::endl;
    }
}

void PrintHelpInfo()
{
    printf("Usage:");
    printf(" -c <file_path> : Specify the path to the file containing iptables rules.\n");
    printf(" -d <file_path> : Specify the path to the file containing DNS database.\n");
    printf(" -l <path> : Specify the path to the log file.\n");
    printf(" -r <region> : Specify the region to filter IP addresses. (0 for china; 1 for other country)\n");
    printf(" -h : Show this help message.\n");
}

void PraseCommandLine(int argc, char** argv) {
    if(argc < 4) {
        PrintHelpInfo();
        exit(EXIT_FAILURE);
    }
    int i;
    for (i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
            std::cout << "Config file path set to: " << config_path << std::endl;
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            db_path = argv[++i];
            std::cout << "Database file path set to: " << db_path << std::endl;
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            log_path = argv[++i];
            std::cout << "Log file path set to: " << log_path << std::endl;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            region = atoi(argv[++i]);
            std::cout << "Region set to: " << region << std::endl;
        } else if (strcmp(argv[i], "-h") == 0) {
            PrintHelpInfo();
            exit(EXIT_SUCCESS);
        } else {
            PrintHelpInfo();
            exit(EXIT_FAILURE);
        }
    }
    if(config_path == nullptr || db_path == nullptr || log_path == nullptr) {
        std::cerr << "Error: Missing required arguments. Please provide -c, -d, and -l options." << std::endl;
        PrintHelpInfo();
        exit(EXIT_FAILURE);
    }
    
}
void* firewall_thread(void* arg) {
    (void)arg;
    if (config_path == nullptr) {
        std::cerr << "Config path is not set. Please provide a valid config file path." << std::endl;
        return nullptr;
    }
    read_file_line(config_path);
    return nullptr;
}

int main(int argc, char** argv) {
    (void)argv;
    int ret = 0;
    do {
        ret = NetdBinderInit();
        if (ret != 0) {
            std::cerr << "Retrying to connect to netd service..." << std::endl;
            sleep(10);  // Wait for 10 seconds before retrying
        }
    } while (ret != 0);

    // 解析命令行参数
    PraseCommandLine(argc, argv);
    set_log_path(log_path);
    set_db_path(db_path);
    set_region(region);
    dns_client_init();
    signal(SIGINT, Stop_And_Exit);
    signal(SIGTERM, Stop_And_Exit);

    pthread_t firewallThread;
    pthread_t mainThread;
    pthread_t udpThread;
    // 创建防火墙线程
    pthread_create(&firewallThread, nullptr, firewall_thread, nullptr);
    // 创建主线程
    pthread_create(&mainThread, nullptr, main_loop, nullptr);
    pthread_create(&udpThread, nullptr, udp_server_loop, nullptr);

    while (1)
    {
        sleep(10);
    }
    
    return EXIT_SUCCESS;
}