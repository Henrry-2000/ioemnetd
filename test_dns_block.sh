#!/system/bin/sh
DEVICE_BIN="/vendor/bin/dns_block_tester"

# 国内域名测试
DOMESTIC_DOMAINS=(
  "www.baidu.com"
  "www.qq.com"
)

# 国外域名测试  
FOREIGN_DOMAINS=(
  "www.google.com"
  "www.youtube.com"
)

echo "=== 测试国内域名（期望：不拦截，getaddrinfo OK） ==="
for d in "${DOMESTIC_DOMAINS[@]}"; do
  echo ">>> Testing: $d"
  echo "Start time: $(date +%s.%N)"
  "$DEVICE_BIN" "$d" 1
  echo "End time: $(date +%s.%N)"
  echo "Exit code: $?"
  echo "----------------------------------------"
  sleep 1  # 在每次测试间添加间隔
done

echo "=== 测试国外域名（期望：被拦截，getaddrinfo 返回错误） ==="
for d in "${FOREIGN_DOMAINS[@]}"; do
  echo ">>> Testing: $d"
  echo "Start time: $(date +%s.%N)"
  "$DEVICE_BIN" "$d" 1
  echo "End time: $(date +%s.%N)"
  echo "Exit code: $?"
  echo "----------------------------------------"
  sleep 1  # 在每次测试间添加间隔
done

echo "=== 测试完成 ==="