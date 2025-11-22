// packages/modules/DnsResolver/IpGeoFilter.cpp
#include "ip_geo_filter.h"
#include "xdb_searcher.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <android-base/logging.h>
#include <android-base/properties.h>   // 新增：读取系统属性
#include <mutex>
#include <unistd.h>  

namespace android {
namespace net {
// 全局开关属性名：true 表示启用境外 IP 拦截，false 表示关闭
// 你可以按需要改成别的，比如 persist.sys.dns_block_foreign
static constexpr const char kPropDnsBlockForeign[] = "persist.vendor.dns_block_foreign";
// 出厂内置路径
static constexpr const char kDbPathSystem[] = "/system/etc/ip2region.xdb";
// 运行时更新路径（updater 往这里写）
static constexpr const char kDbPathData[]   = "/data/system/ip2region.xdb";
static std::once_flag gIpResolverOnce;
// 全局 ip_resolver 相关变量
static xdb_vector_index_t *v_index;
static xdb_searcher_t searcher;

static bool gIpResolverReady = false;

static std::mutex gIpResolverMutex;

enum IpResolverRet {
    IP_RES_OK = 0,
    IP_RES_LOAD_VINDEX_FAILED = 1,
    IP_RES_NEW_SEARCHER_FAILED = 2,
};

// 默认值为 true，属性解析失败时也当 true
static bool isForeignBlockEnabled() {
    // 这里如果属性值格式异常，GetBoolProperty 会返回默认值 true
    return android::base::GetBoolProperty(kPropDnsBlockForeign, true);
}



static void initIpResolverOnce() {
    const char* db_path = nullptr;

    // 如果 /data/system 有新版本，就优先用它
    if (access(kDbPathData, R_OK) == 0) {
        db_path = kDbPathData;
    } else {
        db_path = kDbPathSystem;
    }

    int ret = ip_resolver_init(db_path);
    if (ret == 0) {
        gIpResolverReady = true;
        LOG(INFO) << "IpGeoFilter: ip_resolver_init OK, db=" << db_path;
    } else {
        gIpResolverReady = false;
        LOG(ERROR) << "IpGeoFilter: ip_resolver_init FAILED, ret=" << ret
                   << " db=" << db_path;
    }
}


static void ensureIpResolverInited() {
    std::call_once(gIpResolverOnce, []() {
        initIpResolverOnce();
    });
}


/**
 * @brief ip_resolver初始化函数
 * 
 * @return int 
 */
int ip_resolver_init(const char* db_path) {
    std::lock_guard<std::mutex> lk(gIpResolverMutex);
    if (gIpResolverReady) return IP_RES_OK;
    xdb_vector_index_t* idx = xdb_load_vector_index_from_file(db_path);
    if (!idx) {
        LOG(ERROR) << "failed to load vector index from " << db_path;
        return IP_RES_LOAD_VINDEX_FAILED;
    }
    int err = xdb_new_with_vector_index(&searcher, db_path, idx);
    if (err != 0) {
        LOG(ERROR) << "failed to create searcher err=" << err;
        xdb_close_vector_index(idx);
        return IP_RES_NEW_SEARCHER_FAILED;
    }
    v_index = idx;
    gIpResolverReady = true;
    return IP_RES_OK;
}

/**
 * @brief  释放ip_resolver资源
 * 
 */
void ip_resolver_deinit() {
    std::lock_guard<std::mutex> lk(gIpResolverMutex);
    if (!gIpResolverReady) return;
    xdb_close(&searcher);
    xdb_close_vector_index(v_index);
    v_index = nullptr;
    gIpResolverReady = false;
}

// 判断某特定的IP是否为域外
static bool isForeignIp(const std::string& ip) {
    ensureIpResolverInited();  // 每次判断前先确保初始化，但只会真正跑一次
    if (!gIpResolverReady) {
        return false; // 保守策略
    }
    in_addr v4={};
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        int region = ip_region_lookup(ip.c_str());
        if (region == -1) return false;
        return (region == 0);
    }
    in6_addr v6={};
    if (inet_pton(AF_INET6, ip.c_str(), &v6) == 1) {
        // TODO: 需确认 xdb 支持 IPv6
        // int region = ip_region_lookup(ip.c_str()); // 需确认 xdb 支持 IPv6
        // if (region == -1) return true; // 或 false，按策略决定
        // return (region == 0);
        return false;
    }
    // 无法解析格式：按策略处理
    return true;
}


/**
 * @brief 通过ip字符串查询IP归属地(是否为中国IP)

 * @param ip char* IP地址字符串
 * @param is_china char* 返回值指针，设置为1表示是中国IP，0表示不是中国IP
 * @return int 
 */
// 返回  1 => China, 0 => Not China, -1 => error
int ip_region_lookup(const char* ip) {
    if (!gIpResolverReady) return -1;
    char region_buffer[256] = {0};
    int err = xdb_search_by_string(&searcher, ip, region_buffer, sizeof(region_buffer));
    if (err != 0) {
        LOG(ERROR) << "xdb_search_by_string failed for " << ip << " err=" << err;
        return -1;
    }
    return (strstr(region_buffer, "中国") != nullptr) ? 1 : 0;
}

bool isForeignDomain(const std::string& host,
                     const std::vector<std::string>& ipAddrs,
                     uint32_t uid,
                     pid_t pid) {
    // 读取全局开关
    if (!isForeignBlockEnabled()) {
        return false;
    }

    if (ipAddrs.empty()) {
        // 没解析到 IP，就当“不是境外域名”（交给上层错误处理）
        LOG(INFO) << "IpGeoFilter: no IPs for domain=" << host
                  << " uid=" << uid << " pid=" << pid;
        return false;
    }

    bool hasForeign = false;
    bool hasDomestic = false;

    for (const auto& ip : ipAddrs) {
        bool foreign = isForeignIp(ip);
        if (foreign) {
            hasForeign = true;
        } else {
            hasDomestic = true;
        }
    }

    // 策略 ：只要有一个境外 IP，且没有国内IP，就把整个域名视为“境外”
    // 符合你“境外域名整体拦截”的需求。
    if (!hasDomestic && hasForeign) {
        LOG(INFO) << "IpGeoFilter: block domain=" << host
                  << " uid=" << uid << " pid=" << pid;
        return true;
    }

    // 全是“国内”IP，就放行
    return false;
}

}  // namespace net
}  // namespace android
