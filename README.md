# ioemnetd
安卓防火墙
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
