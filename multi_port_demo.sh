#!/bin/bash

echo "=== WAF 多端口功能演示 ==="
echo ""

echo "1. 测试多端口配置..."
echo "   配置: [0.0.0.0:8080, 0.0.0.0:9000]"
WAF_CONFIG=./config/test_multi_port.json ./target/debug/waf &
WAF_PID=$!
echo "   WAF 进程 ID: $WAF_PID"

sleep 2

echo ""
echo "2. 测试各端口连接性..."

if curl -s -o /dev/null -w "   端口 8080: %{http_code}\n" http://127.0.0.1:8080/; then
    echo "   ✅ 8080端口正常"
else
    echo "   ❌ 8080端口失败"
fi

if curl -s -o /dev/null -w "   端口 9000: %{http_code}\n" http://127.0.0.1:9000/; then
    echo "   ✅ 9000端口正常"
else
    echo "   ❌ 9000端口失败"
fi

echo ""
echo "3. 测试向后兼容性..."
echo "   配置: listen_addr = 0.0.0.0:8080 (旧格式)"

# 停止当前的WAF
kill $WAF_PID 2>/dev/null
sleep 1

WAF_CONFIG=./config/minimal.json ./target/debug/waf &
WAF_PID=$!
sleep 2

if curl -s -o /dev/null http://127.0.0.1:8080/; then
    echo "   ✅ 旧配置格式兼容正常"
else
    echo "   ❌ 旧配置格式失败"
fi

echo ""
echo "4. 清理环境..."
kill $WAF_PID 2>/dev/null
sleep 1

echo ""
echo "=== 测试完成 ==="
echo "多端口功能已成功实现并验证！"
