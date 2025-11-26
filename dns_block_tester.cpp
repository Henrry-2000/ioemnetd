// file: vendor/changan/dns_block_tester/dns_block_tester.cpp
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  

static void print_addrs(struct addrinfo* res) {
    char host[NI_MAXHOST] = {0};
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        void* addr = nullptr;
        const char* family = nullptr;
        if (ai->ai_family == AF_INET) {
            struct sockaddr_in* sa = (struct sockaddr_in*)ai->ai_addr;
            addr = &sa->sin_addr;
            family = "IPv4";
        } else if (ai->ai_family == AF_INET6) {
            struct sockaddr_in6* sa6 = (struct sockaddr_in6*)ai->ai_addr;
            addr = &sa6->sin6_addr;
            family = "IPv6";
        } else {
            continue;
        }
        if (inet_ntop(ai->ai_family, addr, host, sizeof(host))) {
            printf("  %s: %s\n", family, host);
        }
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname> [count]\n", argv[0]);
        return 1;
    }
    const char* hostname = argv[1];
    int count = 1;
    if (argc >= 3) {
        count = atoi(argv[2]);
        if (count <= 0) count = 1;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;      // IPv4 + IPv6
    hints.ai_socktype = SOCK_STREAM;    // 模拟正常 TCP 连接场景
    
    for (int i = 0; i < count; i++) {
        struct addrinfo* res = nullptr;
        int ret = getaddrinfo(hostname, "80", &hints, &res);
        if (ret != 0) {
            printf("Query %d: getaddrinfo(%s) FAILED, ret=%d (%s)\n",
                   i, hostname, ret, gai_strerror(ret));
        } else {
            printf("Query %d: getaddrinfo(%s) OK\n", i, hostname);
            print_addrs(res);
            freeaddrinfo(res);
        }
        
        // 如果不是最后一次查询，稍微等待一下
        if (i < count - 1) {
            usleep(100000); // 等待 100ms
        }
    }
    
    // 关键：在程序退出前稍作等待，确保 DNS 解析器完成所有处理
    printf("Waiting for DNS resolver to complete processing...\n");
    usleep(500000); // 等待 500ms
    
    return 0;
}