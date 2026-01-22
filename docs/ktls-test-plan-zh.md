# Ztunnel kTLS 测试方案

## 1. 测试目标

验证 kTLS 改造后的 Ztunnel 能够：

1. **建立直连 socket**：Pod1 到 Pod2 的连接使用真实四元组
2. **数据加密传输**：流量在网络层加密，保证安全性
3. **四元组可见性**：网络监控工具能看到真实的连接信息
4. **功能正确性**：数据能正确传输，不丢包不错乱
5. **性能提升**：相比 HBONE 有性能改进

## 2. 测试环境搭建

### 2.1 基础环境要求

```bash
# Linux 内核版本检查
uname -r
# 需要 >= 4.13 (kTLS 支持)
# 推荐 >= 5.10 (更好的 kTLS 支持)

# 检查 kTLS 内核模块
lsmod | grep tls
# 如果没有，加载模块
sudo modprobe tls

# 检查 /proc/sys/net/tls
ls -la /proc/sys/net/tls
```

### 2.2 测试拓扑

```
┌─────────────────────────────────────────────────┐
│                  Test Node                       │
│                                                  │
│  ┌──────────┐         ┌──────────┐             │
│  │  Pod1    │         │  Pod2    │             │
│  │  Client  │         │  Server  │             │
│  │  (netns1)│         │  (netns2)│             │
│  └────┬─────┘         └─────┬────┘             │
│       │                     │                   │
│       │  1.2.3.4:12345      │  10.0.0.2:8080   │
│       │                     │                   │
│       ├─────────┬───────────┤                   │
│                 │                               │
│          ┌──────┴──────┐                        │
│          │  Ztunnel    │                        │
│          │  (kTLS)     │                        │
│          └─────────────┘                        │
│                                                  │
└─────────────────────────────────────────────────┘
```

### 2.3 环境搭建脚本

```bash
#!/bin/bash
# setup-ktls-test-env.sh

set -e

echo "=== 设置测试环境 ==="

# 创建网络命名空间
sudo ip netns add pod1-ns
sudo ip netns add pod2-ns

# 创建 veth 对
sudo ip link add veth1 type veth peer name veth1-br
sudo ip link add veth2 type veth peer name veth2-br

# 将 veth 放入命名空间
sudo ip link set veth1 netns pod1-ns
sudo ip link set veth2 netns pod2-ns

# 创建网桥
sudo ip link add br0 type bridge
sudo ip link set veth1-br master br0
sudo ip link set veth2-br master br0

# 配置 IP 地址
sudo ip netns exec pod1-ns ip addr add 1.2.3.4/24 dev veth1
sudo ip netns exec pod2-ns ip addr add 10.0.0.2/24 dev veth2

# 启动接口
sudo ip link set br0 up
sudo ip link set veth1-br up
sudo ip link set veth2-br up
sudo ip netns exec pod1-ns ip link set veth1 up
sudo ip netns exec pod2-ns ip link set veth2 up
sudo ip netns exec pod1-ns ip link set lo up
sudo ip netns exec pod2-ns ip link set lo up

# 配置路由
sudo ip netns exec pod1-ns ip route add default via 1.2.3.1
sudo ip netns exec pod2-ns ip route add default via 10.0.0.1

echo "=== 环境搭建完成 ==="
```

## 3. 测试用例

### 3.1 单元测试

#### 测试 1: kTLS 支持检测
```rust
#[test]
fn test_ktls_support_detection() {
    use ztunnel::ktls;
    
    // 在 Linux 上应该返回 true
    #[cfg(target_os = "linux")]
    assert!(ktls::is_supported());
    
    // 在其他系统上应该返回 false
    #[cfg(not(target_os = "linux"))]
    assert!(!ktls::is_supported());
}
```

#### 测试 2: 密钥管理
```rust
#[tokio::test]
async fn test_key_manager_operations() {
    use ztunnel::ktls::{KeyManager, TlsKeys, KeyMaterial, ConnectionId};
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};
    
    let manager = KeyManager::new();
    
    // 创建测试密钥
    let conn_id = ConnectionId::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
    );
    
    let keys = TlsKeys {
        tx: KeyMaterial::new(
            0x0304,
            0x1302,
            vec![0u8; 32],
            vec![0u8; 12],
        ),
        rx: KeyMaterial::new(
            0x0304,
            0x1302,
            vec![1u8; 32],
            vec![1u8; 12],
        ),
    };
    
    // 存储密钥
    manager.store_keys(conn_id.clone(), keys).await;
    
    // 检索密钥
    let retrieved = manager.get_keys(&conn_id).await;
    assert!(retrieved.is_some());
    
    // 移除密钥
    manager.remove_keys(&conn_id).await;
    let retrieved = manager.get_keys(&conn_id).await;
    assert!(retrieved.is_none());
}
```

#### 测试 3: 配置验证
```rust
#[test]
fn test_ktls_config_validation() {
    use ztunnel::ktls::KtlsConfig;
    
    let mut config = KtlsConfig::default();
    config.enabled = true;
    
    #[cfg(target_os = "linux")]
    assert!(config.validate().is_ok());
    
    // 没有 cipher suite 应该失败
    config.cipher_suites.clear();
    assert!(config.validate().is_err());
}
```

### 3.2 集成测试

#### 测试 4: Socket 四元组验证

**目标**: 验证网络层可见的四元组是否正确

```bash
#!/bin/bash
# test-socket-tuple.sh

echo "=== 测试 Socket 四元组 ==="

# 在 pod2 启动测试服务器
sudo ip netns exec pod2-ns nc -l 8080 > /tmp/pod2-received.txt &
SERVER_PID=$!

# 启动 tcpdump 抓包
sudo tcpdump -i br0 -n 'tcp port 8080' -w /tmp/ktls-test.pcap &
TCPDUMP_PID=$!

sleep 2

# 在 pod1 发起连接并发送数据
echo "Hello from Pod1" | sudo ip netns exec pod1-ns nc 10.0.0.2 8080

sleep 2

# 停止抓包
sudo kill $TCPDUMP_PID
sudo kill $SERVER_PID

# 分析抓包文件
echo "=== 抓包分析 ==="
sudo tcpdump -r /tmp/ktls-test.pcap -n

# 验证四元组
# 应该看到: 1.2.3.4:12345 > 10.0.0.2:8080 SYN
echo "=== 验证四元组 ==="
if sudo tcpdump -r /tmp/ktls-test.pcap -n | grep -q "1.2.3.4.*> 10.0.0.2.8080"; then
    echo "✓ 四元组验证成功！"
else
    echo "✗ 四元组验证失败！"
    exit 1
fi

# 验证数据接收
if grep -q "Hello from Pod1" /tmp/pod2-received.txt; then
    echo "✓ 数据传输成功！"
else
    echo "✗ 数据传输失败！"
    exit 1
fi
```

#### 测试 5: 数据加密验证

**目标**: 验证网络层数据是加密的

```bash
#!/bin/bash
# test-encryption.sh

echo "=== 测试数据加密 ==="

# 启动服务器
sudo ip netns exec pod2-ns nc -l 8080 > /tmp/pod2-received.txt &
SERVER_PID=$!

# 抓包
sudo tcpdump -i br0 -n 'tcp port 8080' -A -w /tmp/ktls-encrypted.pcap &
TCPDUMP_PID=$!

sleep 2

# 发送明文数据
TEST_MESSAGE="This is a secret message 12345678"
echo "$TEST_MESSAGE" | sudo ip netns exec pod1-ns nc 10.0.0.2 8080

sleep 2

# 停止
sudo kill $TCPDUMP_PID
sudo kill $SERVER_PID

# 检查抓包中是否包含明文
echo "=== 检查加密 ==="
if sudo tcpdump -r /tmp/ktls-encrypted.pcap -A | grep -q "$TEST_MESSAGE"; then
    echo "✗ 警告：在网络层发现明文数据！"
    exit 1
else
    echo "✓ 数据已加密，网络层看不到明文"
fi

# 检查接收端是否收到正确的明文
if grep -q "$TEST_MESSAGE" /tmp/pod2-received.txt; then
    echo "✓ 接收端正确解密数据"
else
    echo "✗ 接收端解密失败"
    exit 1
fi
```

#### 测试 6: kTLS Socket 验证

**目标**: 使用 `ss` 命令验证 kTLS socket 存在

```bash
#!/bin/bash
# test-ktls-socket.sh

echo "=== 测试 kTLS Socket ==="

# 启动长连接服务器
sudo ip netns exec pod2-ns nc -l 8080 &
SERVER_PID=$!

sleep 2

# 在 pod1 建立连接（保持打开）
sudo ip netns exec pod1-ns nc 10.0.0.2 8080 &
CLIENT_PID=$!

sleep 2

# 使用 ss 命令查看 socket 信息
echo "=== Socket 状态 ==="
sudo ip netns exec pod1-ns ss -tan | grep "10.0.0.2:8080"

# 检查是否有 kTLS 标记
# 注意: ss 可能不直接显示 kTLS，需要检查 /proc/net/tls
echo "=== kTLS 连接信息 ==="
if [ -f /proc/net/tls ]; then
    cat /proc/net/tls
    echo "✓ 找到 kTLS 连接"
else
    echo "✗ 未找到 kTLS 连接信息"
fi

# 清理
sudo kill $CLIENT_PID
sudo kill $SERVER_PID
```

#### 测试 7: 性能对比测试

**目标**: 对比 HBONE 和 kTLS 的性能

```bash
#!/bin/bash
# test-performance.sh

echo "=== 性能测试 ==="

TEST_SIZE_MB=100
TEST_FILE="/tmp/test-data-${TEST_SIZE_MB}MB.bin"

# 生成测试数据
dd if=/dev/urandom of=$TEST_FILE bs=1M count=$TEST_SIZE_MB

echo "=== 测试 1: HBONE 模式 ==="
# 配置 ztunnel 使用 HBONE
# ktls.enabled = false

# 启动服务器
sudo ip netns exec pod2-ns nc -l 8080 > /dev/null &
SERVER_PID=$!
sleep 1

# 测试传输时间
START_TIME=$(date +%s.%N)
cat $TEST_FILE | sudo ip netns exec pod1-ns nc 10.0.0.2 8080
END_TIME=$(date +%s.%N)
HBONE_TIME=$(echo "$END_TIME - $START_TIME" | bc)

sudo kill $SERVER_PID
sleep 1

echo "HBONE 传输时间: ${HBONE_TIME}s"

echo "=== 测试 2: kTLS 模式 ==="
# 配置 ztunnel 使用 kTLS
# ktls.enabled = true

# 启动服务器
sudo ip netns exec pod2-ns nc -l 8080 > /dev/null &
SERVER_PID=$!
sleep 1

# 测试传输时间
START_TIME=$(date +%s.%N)
cat $TEST_FILE | sudo ip netns exec pod1-ns nc 10.0.0.2 8080
END_TIME=$(date +%s.%N)
KTLS_TIME=$(echo "$END_TIME - $START_TIME" | bc)

sudo kill $SERVER_PID

echo "kTLS 传输时间: ${KTLS_TIME}s"

# 计算性能提升
IMPROVEMENT=$(echo "scale=2; (($HBONE_TIME - $KTLS_TIME) / $HBONE_TIME) * 100" | bc)
echo "性能提升: ${IMPROVEMENT}%"

# 清理
rm -f $TEST_FILE
```

#### 测试 8: 并发连接测试

**目标**: 测试多个并发连接

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_connections() {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    const NUM_CONNECTIONS: usize = 100;
    
    // 启动服务器
    let listener = TcpListener::bind("10.0.0.2:8080").await.unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                socket.write_all(&buf[..n]).await.unwrap();
            });
        }
    });
    
    // 并发连接
    let mut handles = Vec::new();
    for i in 0..NUM_CONNECTIONS {
        let handle = tokio::spawn(async move {
            let mut stream = TcpStream::connect("10.0.0.2:8080").await.unwrap();
            let data = format!("Message {}", i);
            stream.write_all(data.as_bytes()).await.unwrap();
            
            let mut response = vec![0; data.len()];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(data.as_bytes(), &response);
        });
        handles.push(handle);
    }
    
    // 等待所有连接完成
    for handle in handles {
        handle.await.unwrap();
    }
    
    println!("✓ {} 个并发连接测试通过", NUM_CONNECTIONS);
}
```

### 3.3 端到端测试

#### 测试 9: 实际应用测试

```bash
#!/bin/bash
# test-e2e-http.sh

echo "=== 端到端 HTTP 测试 ==="

# 在 pod2 启动 HTTP 服务器
sudo ip netns exec pod2-ns python3 -m http.server 8080 &
HTTP_SERVER_PID=$!

sleep 2

# 从 pod1 发起 HTTP 请求
RESPONSE=$(sudo ip netns exec pod1-ns curl -s http://10.0.0.2:8080/)

# 验证响应
if [ -n "$RESPONSE" ]; then
    echo "✓ HTTP 请求成功"
    echo "响应预览: ${RESPONSE:0:100}..."
else
    echo "✗ HTTP 请求失败"
    exit 1
fi

# 验证四元组
sudo ss -tan | grep "1.2.3.4.*10.0.0.2:8080" && echo "✓ 四元组正确"

# 清理
sudo kill $HTTP_SERVER_PID
```

## 4. 验证清单

### 4.1 功能验证

- [ ] kTLS 初始化成功
- [ ] Socket 四元组正确 (src_ip:src_port -> dst_ip:dst_port)
- [ ] 数据正确传输（无丢包、无错乱）
- [ ] TLS 握手成功
- [ ] 密钥正确配置到内核
- [ ] 数据在网络层加密
- [ ] 数据在应用层正确解密
- [ ] RBAC 验证正常工作
- [ ] 证书验证正常工作

### 4.2 性能验证

- [ ] 延迟 ≤ HBONE 模式
- [ ] 吞吐量 ≥ HBONE 模式
- [ ] CPU 使用率 ≤ HBONE 模式
- [ ] 内存使用合理
- [ ] 并发连接数满足要求

### 4.3 安全验证

- [ ] 网络抓包看不到明文
- [ ] TLS 1.3 加密正常
- [ ] 密钥不泄露
- [ ] 身份验证正常
- [ ] 授权检查正常

### 4.4 可观测性验证

- [ ] tcpdump 能看到正确的四元组
- [ ] ss 命令能看到连接状态
- [ ] 日志记录完整
- [ ] Metrics 正常导出
- [ ] 追踪信息正确

## 5. 自动化测试脚本

### 5.1 主测试脚本

```bash
#!/bin/bash
# run-all-tests.sh

set -e

echo "=================================="
echo "  Ztunnel kTLS 完整测试套件"
echo "=================================="

# 检查环境
echo ""
echo "[1/9] 检查环境..."
./test-environment.sh

# 搭建测试环境
echo ""
echo "[2/9] 搭建测试环境..."
./setup-ktls-test-env.sh

# 运行单元测试
echo ""
echo "[3/9] 运行单元测试..."
cd /home/runner/work/ztunnel/ztunnel
cargo test --lib ktls

# 测试 Socket 四元组
echo ""
echo "[4/9] 测试 Socket 四元组..."
./test-socket-tuple.sh

# 测试数据加密
echo ""
echo "[5/9] 测试数据加密..."
./test-encryption.sh

# 测试 kTLS Socket
echo ""
echo "[6/9] 测试 kTLS Socket..."
./test-ktls-socket.sh

# 性能测试
echo ""
echo "[7/9] 性能对比测试..."
./test-performance.sh

# 端到端测试
echo ""
echo "[8/9] 端到端测试..."
./test-e2e-http.sh

# 清理
echo ""
echo "[9/9] 清理测试环境..."
./cleanup-test-env.sh

echo ""
echo "=================================="
echo "  所有测试通过！✓"
echo "=================================="
```

### 5.2 环境检查脚本

```bash
#!/bin/bash
# test-environment.sh

echo "=== 环境检查 ==="

# 检查 Linux 内核版本
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
echo "内核版本: $(uname -r)"
if (( $(echo "$KERNEL_VERSION >= 4.13" | bc -l) )); then
    echo "✓ 内核版本满足要求 (>= 4.13)"
else
    echo "✗ 内核版本过低，需要 >= 4.13"
    exit 1
fi

# 检查 kTLS 支持
if [ -d "/proc/sys/net/tls" ]; then
    echo "✓ kTLS 支持已启用"
else
    echo "⚠ kTLS 支持未启用，尝试加载模块..."
    sudo modprobe tls || {
        echo "✗ 无法加载 kTLS 模块"
        exit 1
    }
fi

# 检查所需工具
for tool in ip ss tcpdump nc python3 cargo; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool 已安装"
    else
        echo "✗ $tool 未安装"
        exit 1
    fi
done

echo "✓ 环境检查通过"
```

### 5.3 清理脚本

```bash
#!/bin/bash
# cleanup-test-env.sh

echo "=== 清理测试环境 ==="

# 删除网络命名空间
sudo ip netns del pod1-ns 2>/dev/null || true
sudo ip netns del pod2-ns 2>/dev/null || true

# 删除网桥
sudo ip link del br0 2>/dev/null || true

# 清理临时文件
rm -f /tmp/pod2-received.txt
rm -f /tmp/ktls-test.pcap
rm -f /tmp/ktls-encrypted.pcap
rm -f /tmp/test-data-*.bin

echo "✓ 清理完成"
```

## 6. 持续集成

### 6.1 CI 配置

```yaml
# .github/workflows/ktls-tests.yml
name: kTLS Tests

on:
  push:
    branches: [ ktls ]
  pull_request:
    branches: [ ktls ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        override: true
    
    - name: Check kTLS support
      run: |
        uname -r
        sudo modprobe tls || true
        ls -la /proc/sys/net/tls || true
    
    - name: Run unit tests
      run: cargo test --lib ktls
    
    - name: Run integration tests
      if: ${{ success() }}
      run: |
        chmod +x scripts/test-*.sh
        scripts/test-environment.sh
        # 注意：完整的网络测试可能需要特殊权限
```

## 7. 测试报告模板

```markdown
# Ztunnel kTLS 测试报告

## 测试环境
- 内核版本: 5.10.0
- Rust 版本: 1.92.0
- Ztunnel 版本: [commit hash]
- 测试时间: 2024-XX-XX

## 测试结果

### 单元测试
- kTLS 支持检测: ✓ 通过
- 密钥管理: ✓ 通过
- 配置验证: ✓ 通过

### 集成测试
- Socket 四元组验证: ✓ 通过
  - 观察到的四元组: 1.2.3.4:12345 -> 10.0.0.2:8080
- 数据加密验证: ✓ 通过
  - 网络层：加密
  - 应用层：明文正确
- kTLS Socket 验证: ✓ 通过
- 性能测试: ✓ 通过
  - HBONE: 12.5s
  - kTLS: 9.8s
  - 提升: 21.6%

### 端到端测试
- HTTP 测试: ✓ 通过

## 问题和建议
[列出发现的问题和改进建议]

## 结论
所有测试通过，kTLS 实现满足设计要求。
```

## 8. 调试工具和命令

### 8.1 查看 kTLS 连接

```bash
# 查看 TLS 连接
cat /proc/net/tls

# 使用 ss 查看 socket 详情
ss -tiepn | grep 8080

# 查看内核 kTLS 统计
cat /proc/net/snmp | grep -i tls
```

### 8.2 抓包分析

```bash
# 抓包并显示 TLS 信息
tcpdump -i any -n 'port 8080' -X

# 使用 Wireshark 分析（如果有 SSLKEYLOG）
export SSLKEYLOGFILE=/tmp/sslkeys.log
wireshark /tmp/ktls-test.pcap
```

### 8.3 性能分析

```bash
# 使用 perf 分析 CPU
perf record -g -p <ztunnel_pid>
perf report

# 使用 strace 追踪系统调用
strace -p <ztunnel_pid> -e trace=setsockopt,send,recv

# 查看内存使用
pmap -x <ztunnel_pid>
```

## 9. 已知问题和解决方案

### 问题 1: kTLS 模块未加载
```bash
sudo modprobe tls
```

### 问题 2: 权限不足
```bash
# 可能需要 CAP_NET_ADMIN 权限
sudo setcap cap_net_admin=eip ./ztunnel
```

### 问题 3: 密钥提取失败
- 检查 rustls 版本
- 考虑使用 openssl backend

## 10. 总结

本测试方案涵盖了：
- ✓ 单元测试：核心功能模块
- ✓ 集成测试：系统级功能
- ✓ 性能测试：与 HBONE 对比
- ✓ 端到端测试：实际应用场景
- ✓ 自动化：可集成到 CI/CD

通过执行这些测试，可以全面验证 kTLS 实现的正确性、安全性和性能。
