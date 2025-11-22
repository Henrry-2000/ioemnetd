// packages/modules/DnsResolver/IpGeoFilter.h
#pragma once

#include <string>
#include <vector>

#include <sys/types.h>

namespace android {
namespace net {

// 返回 true 表示“这个域名应该被视为境外（需要拦截）”
bool isForeignDomain(const std::string& host,
                     const std::vector<std::string>& ipAddrs,
                     uint32_t uid,
                     pid_t pid);

}  // namespace net
}  // namespace android
