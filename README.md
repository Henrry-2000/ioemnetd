# ioemnetd

安卓防火墙介绍：Netd是Android的网络守护进程。封装了复杂的底层各种类型的网络(NAT，PLAN，PPP，SOFTAP，TECHER，ETHO，MDNS等)，隔离了底层网络接口的差异，给Framework提供了统一调用接口，简化了网络的使用。Netd主要功能是:第一、接收Framework的网络请求，处理请求，向Framework层反馈处理结果；第二、监听网络事件(断开/连接/错误等)，向Framework层上报。本方案将加载防火墙规则的接口实现在Netd组件中。通过在Oemnetd中添加加载防火墙规则的接口，并由客户端进程读取配置文件，调用加载接口，实现系统防火墙的加载。
针对配置文件读取异常的情况，将采用读取备份规则的方式进行加载,并记录配置文件读取失败的情况。
针对单条规则加载失败的情况，会至多重复加载三次，如都失败，则记录该条异常规则。
```
注：
1）Oemnetd为netd中厂商定制服务接口，可实现定制化功能。
2）execIptablesRestore为netd中执行防火墙的接口，其本质为调用iptables-restore命令。
```
netd源码在安卓源码对应的system/netd下
1、在oemnetd的aidl文件IOemNetd.aidl中添加接口set_iptables_rules，第一个参数为加载ipv4或者ipv6或两者都加载，第二个参数为防火墙的type，分为filter，mangle及nat三种，第三个参数为防火墙规则。
```
#
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

## 0、将工程文件解压到aosp根路径下的system/netd/中
## 1、初始化环境
```
source build/envsetup.sh 
lunch aosp_x86_64 trunk_staging eng
export USE_CCACHE=1
```
## 2、编译当前模块
```
cd system/netd/ioemnetd
mma -j1
```
## 3、生成的文件会在./out/target/product/generic_arm64/system/bin/ioemnetd

## 4、把oemListener.cpp以及oemListener.h文件放在 system/netd/server 下

## 5、把IOemNetd.aidl放在system/netd/server/binder/com/android/internal/net 下

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
