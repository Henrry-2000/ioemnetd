# ioemnetd
安卓防火墙
## 0、将工程文件解压到aosp根路径下的system/netd/中
## 1、初始化环境
```
source build/envsetup.sh 
lunch 2
```
## 2、编译当前模块
```
cd system/netd/ioemnetd
mma
```
## 3、生成的文件会在./out/target/product/generic_arm64/system/bin/ioemnetd
