# ioemnetd
ioemnetd 代码仓库包含安卓防火墙以及DNS服务。
## 安卓防火墙介绍
Netd是Android的网络守护进程。封装了复杂的底层各种类型的网络(NAT，PLAN，PPP，SOFTAP，TECHER，ETHO，MDNS等)，隔离了底层网络接口的差异，给Framework提供了统一调用接口，简化了网络的使用。

Netd主要功能是:第一、接收Framework的网络请求，处理请求，向Framework层反馈处理结果；第二、监听网络事件(断开/连接/错误等)，向Framework层上报。本方案将加载防火墙规则的接口实现在Netd组件中。通过在Oemnetd中添加加载防火墙规则的接口，并由客户端进程读取配置文件，调用加载接口，实现系统防火墙的加载。


针对配置文件读取异常的情况，将采用读取备份规则的方式进行加载,并记录配置文件读取失败的情况。
针对单条规则加载失败的情况，会至多重复加载三次，如都失败，则记录该条异常规则。注：
```
1）Oemnetd为netd中厂商定制服务接口，可实现定制化功能。
2）execIptablesRestore为netd中执行防火墙的接口，其本质为调用iptables-restore命令。
```
netd源码在安卓源码对应的system/netd下
1、在oemnetd的aidl文件IOemNetd.aidl中添加接口set_iptables_rules，第一个参数为加载ipv4或者ipv6或两者都加载，第二个参数为防火墙的type，分为filter，mangle及nat三种，第三个参数为防火墙规则。

```
/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.net;

import com.android.internal.net.IOemNetdUnsolicitedEventListener;

/** {@hide} */
interface IOemNetd {
    /**
     * Returns true if the service is responding.
     */
    boolean isAlive();

    /**
     * Register oem unsolicited event listener
     *
     * @param listener oem unsolicited event listener to register
     */
    void registerOemUnsolicitedEventListener(IOemNetdUnsolicitedEventListener listener);

    String set_iptables_rules(int v4v6, int type, String rules);
}
```
2、在OemNetdListener.cpp、OemNetdListener.h中添加set_iptables_rules的实现
3、实现客户端，读取配置文件，调用oemnetd中的接口加载防火墙
1）初始化服务
```
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
```
2）读取配置文件，并调用接口加载规则
```
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
```

## DNS服务配置方案
### DNS服务器方案设计
DNS服务器应配置IP访问控制策略，仅允许符合规定的国内IP地址访问DNS服务。所有境外IP访问请求应被阻止，防止潜在的安全风险。 
DnsResolver是安卓系统中的DNS解析器，该解析器可将www.google.com等名称转换为IP地址。本方案通过修改DnsResolver的源码，保存一份解析的结果，通过UDP协议，走本地回环地址(127.0.0.1:19330)，将解析数据发送到DNS_Client。DNS_Client接收到解析数据后，通过开源组件[ip2region](https://github.com/lionsoul2014/ip2region.git)，本地查询ip归属地是否为国内，如出现非法归属地，将记录安全事件(事件信息包括查询的进程、PID、UID、域名、IP等)。注：查询采用本地数据库查询方式，要获取每月更新的最新IP数据，需付费[订阅](https://ip2region.net/products/offline)。

### DNS服务器代码实现
修改DnsResolver的源码，源码路径在：`packages/modules/DnsResolver` 下

1）添加sendUdpPacket函数，发送解析结果
```
static void sendUdpPacket(std::string data) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG(ERROR) << "UDP socket creation failed: " << strerror(errno);
        return;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(19330);

    if (inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr) <= 0) {
        LOG(ERROR) << "inet_pton failed";
        close(sockfd);
        return;
    }

    ssize_t sent = sendto(sockfd, data.c_str(), data.size() + 1, 0,
                          (const struct sockaddr*)&servaddr, sizeof(servaddr));
    if (sent < 0) {
        LOG(ERROR) << "UDP send failed: " << strerror(errno);
    }

    close(sockfd);
}
```
2）在DNS解析函数中，添加获取DNS解析结果并发送的代码，关键代码片段如下：
```
void DnsProxyListener::GetAddrInfoHandler::run() {
    LOG(INFO) << "GetAddrInfoHandler::run: {" << mNetContext.toString() << "}";
    addrinfo* result = nullptr;
    Stopwatch s;
    maybeFixupNetContext(&mNetContext, mClient->getPid());
    const uid_t uid = mClient->getUid();
    int32_t pid = mClient->getPid(); //获取pid
    int32_t rv = 0;
    InitDnsEventReport(mNetContext);
    if (!startQueryLimiter(uid)) {
        const char* host = mHost.starts_with("^") ? nullptr : mHost.c_str();
        const char* service = mService.starts_with("^") ? nullptr : mService.c_str();
        if (evaluate_domain_name(mNetContext, host)) {
            rv = resolv_getaddrinfo(host, service, mHints.get(), &mNetContext, &result, &event);
        } else {
            rv = EAI_SYSTEM;
        }
        endQueryLimiter(uid);
    } else {
        // Note that this error code is currently not passed down to the client.
        // android_getaddrinfo_proxy() returns EAI_NODATA on any error.
        rv = EAI_ERROR;
        LOG(ERROR) << "GetAddrInfoHandler::run: from UID " << uid
                   << ", max concurrent queries reached";
    }
// 这里省略11行
    success = mClient->sendBinaryMsg(ResponseCode::DnsProxyOperationFailed, &rv, sizeof(rv));
} else {
    success = mClient->sendCode(ResponseCode::DnsProxyQueryResult);
    addrinfo* ai = result;
    while (ai && success) {
        success = sendBE32(mClient, 1) && sendaddrinfo(mClient, ai);
        ai = ai->ai_next;
    }
    success = success && sendBE32(mClient, 0);
}

if (!success) {
    PLOG(WARNING) << "GetAddrInfoHandler::run: Error writing DNS result to client uid " << uid
                  << " pid " << mClient->getPid();
}

std::vector<std::string> ip_addrs;
const int total_ip_addr_count = extractGetAddrInfoAnswers(result, &ip_addrs);
std::string buf;
if(total_ip_addr_count > 0)
{
    buf += "DnsRet:success,domain:";
    buf += mHost;
    buf += ",UID:";
    buf += std::to_string(uid);
    buf += ",PID:";
    buf += std::to_string(pid);
    buf += ",";
    if(!ip_addrs.empty())
    {
        for(size_t i = 0; i < ip_addrs.size();i++)
        {
            buf+=ip_addrs[i];
            buf+=",";
        }
    }
    LOG(INFO) << buf;
    sendUdpPacket(buf); //调用sendUdpPacket 发送udp报文，包含DNS解析结果
}

reportDnsEvent(InetdEventListener::EVENT_GETADDRINFO, mNetContext, latencyUs, rv, event, mHost,
               ip_addrs, total_ip_addr_count);
freeaddrinfo(result);
```

### 境外IP拦截方案设计与实现
在`dns_client.c`中添加发送DNS Refuse UDP报文的函数：
```

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
```
在`dns_client.c`中添加`is_china_ip`函数判断是否是境内IP：
```
// Returns: 1 if China/domestic, 0 if foreign, -1 on error
int is_china_ip(const char* ip) {
    if (!ip) return -1;
    char is_china = 0;
    // search_ip_string expects char* ip and char* is_china
    int rc = search_ip_string((char*)ip, &is_china);
    if (rc != 0) return -1; // lookup failed
    return (is_china == 1) ? 1 : 0;
}
```
在 dns_client.c的`main_loop`函数中中添加拒绝逻辑：
```
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
```
## 初始化步骤
0、将工程文件解压到aosp根路径下的system/netd/中
1、初始化环境
```
source build/envsetup.sh 
lunch aosp_x86_64 trunk_staging eng
export USE_CCACHE=1
```
2、编译当前模块
```
cd system/netd/ioemnetd
mma -j1
```
3、生成的文件会在`./out/target/product/generic_arm64/system/bin/ioemnetd`中

4、把oemListener.cpp以及oemListener.h文件放在 `system/netd/server` 下

5、把IOemNetd.aidl放在`system/netd/server/binder/com/android/internal/net`下

## 关于OOM问题
0. 问题确认
```
dmesg | egrep -i 'killed process|out of memory|oom' -n | tail -n 50
dmesg | grep -i soong_build -n || true
```
如果出现 Out of memory 等相关字样，基本可以判断是内存不足。
1. 清理编译指令的输出文件
```
rm -rf out/soong  
```
2. 设置更大的Mem和Swap
在Windows的$userfile$/.wslconfig 文件中配置如下内容：
```
[wsl2]
memory=14GB        # 给 WSL 分配 14GB 内存（可根据你宿主总内存调整）
processors=6       # 分配 CPU 内核数（按宿主核数调整）
swap=32GB          # 分配 32GB swap
swapFile=C:\\Users\\Henry\\wsl_swap.vhdx
localhostForwarding=true
```
3. 在powershell（管理员身份运行）中
```
wsl --shutdown
```
4. 重新打开wsl
```
cd ~/aosp-download/aosp

# 加载构建环境（必须）
source build/envsetup.sh

# 选择 target（和你之前一样）
lunch aosp_x86_64 trunk_staging eng

# （可选）启用 ccache
export USE_CCACHE=1
ccache -s       # 检查状态

# 在 AOSP 根目录构建指定模块（方法 A：在根目录用 mmm）
mmm system/netd/ioemnetd -j1

```
