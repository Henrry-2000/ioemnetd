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

// 默认值为 true，属性解析失败时也当 true
static bool isForeignBlockEnabled() {
    // 这里如果属性值格式异常，GetBoolProperty 会返回默认值 true
    return android::base::GetBoolProperty(kPropDnsBlockForeign, true);
}



static void initIpResolverOnce() {
    const char* dbPath = nullptr;

    // 如果 /data/system 有新版本，就优先用它
    if (access(kDbPathData, R_OK) == 0) {
        dbPath = kDbPathData;
    } else {
        dbPath = kDbPathSystem;
    }

    int ret = ip_resolver_init(dbPath);
    if (ret == 0) {
        gIpResolverReady = true;
        LOG(INFO) << "IpGeoFilter: ip_resolver_init OK, db=" << dbPath;
    } else {
        gIpResolverReady = false;
        LOG(ERROR) << "IpGeoFilter: ip_resolver_init FAILED, ret=" << ret
                   << " db=" << dbPath;
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
int ip_resolver_init(const char* dbPath)
{
    // 初始化ip_resolver
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
 * @brief  释放ip_resolver资源
 * 
 */
void ip_resolver_deinit()
{
    xdb_close(&searcher);
    xdb_close_vector_index(v_index);
}

// 判断某特定的IP是否为域外
static bool isForeignIp(const std::string& ip) {
    ensureIpResolverInited();  // 每次判断前先确保初始化，但只会真正跑一次

    in_addr v4{};
    if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
        uint32_t hostOrder = ntohl(v4.s_addr);

        // 初始化失败时，策略你自己选：
        if (!gIpResolverReady) {
            // 保守策略：初始化失败也当做不是境外
            return false;
        }
        char* isChina = 0;
        int ret = search_ip_string(ip.c_str(), &isChina);
        if (ret == 0)
        {
            return (isChina == 0); // 不是中国 IP => “境外”
        }
        // 查询失败时，认为不是境外
        return false;
    }

    // TODO:IPv6 暂时全部当境外，或者后续扩展
    return true;
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
