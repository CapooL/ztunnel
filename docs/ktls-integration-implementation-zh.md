# kTLS 集成实施方案

## 实施概述

本文档详细说明如何将 kTLS 模块集成到 Ztunnel 的 outbound 和 inbound 数据路径中。

## 1. 核心挑战：密钥提取

### 问题描述

rustls 默认不暴露 TLS 会话密钥，这是最大的技术挑战。

### 解决方案

**阶段 1：预共享密钥方案（当前实施）**

使用 `KeyManager` 预先配置密钥，绕过自动提取问题：

```rust
// 在 Node X 和 Node Y 上配置相同的密钥
let key_manager = KeyManager::new();
let conn_id = ConnectionId::new(pod1_addr, pod2_addr);
key_manager.store_keys(conn_id, tls_keys).await;
```

**阶段 2：自动密钥提取（未来工作）**

切换到 OpenSSL backend，使用 `SSL_export_keying_material` API。

## 2. 代码改造点

### 2.1 创建密钥提取模块

**文件**: `src/ktls/key_extraction.rs` ✅

提供多种密钥提取策略：
- `PreShared`: 从 KeyManager 获取预配置密钥
- `SslKeyLog`: 从 SSLKEYLOGFILE 读取（调试用）
- `Mock`: 测试用模拟密钥

### 2.2 修改 ProxyInputs 结构

**文件**: `src/proxy.rs`

需要添加 kTLS 相关字段：

```rust
pub struct ProxyInputs {
    // ... 现有字段
    
    // kTLS支持
    pub key_manager: Option<Arc<KeyManager>>,
    pub key_extractor: Option<Arc<KeyExtractor>>,
}
```

### 2.3 修改 Outbound 处理

**文件**: `src/proxy/outbound.rs`

**当前代码** (第 99-120 行):
```rust
let mut oc = OutboundConnection {
    pi: self.pi.clone(),
    id: TraceParent::new(),
    pool: pool.clone(),
    hbone_port: self.pi.cfg.inbound_addr.port(),
};
// ... 调用 oc.proxy(stream)
```

**需要修改为**:
```rust
// 检查是否启用 kTLS
if self.pi.cfg.ktls.enabled && self.pi.cfg.ktls.outbound_enabled {
    // kTLS 路径
    let ktls_handler = KtlsOutboundHandler::new(
        self.pi.clone(),
        self.pi.key_extractor.as_ref().unwrap().clone(),
    );
    ktls_handler.handle(stream).await?;
} else {
    // 保留原有 HBONE 路径
    let mut oc = OutboundConnection {
        pi: self.pi.clone(),
        id: TraceParent::new(),
        pool: pool.clone(),
        hbone_port: self.pi.cfg.inbound_addr.port(),
    };
    oc.proxy(stream).await?;
}
```

### 2.4 创建 KtlsOutboundHandler

**文件**: `src/proxy/outbound_ktls.rs` (新文件)

```rust
pub struct KtlsOutboundHandler {
    pi: Arc<ProxyInputs>,
    key_extractor: Arc<KeyExtractor>,
}

impl KtlsOutboundHandler {
    pub async fn handle(&self, stream: TcpStream) -> Result<(), Error> {
        // 1. 获取原始目标地址
        let orig_dst = get_original_dst(&stream)?;
        
        // 2. 查询目标工作负载
        let workload = self.pi.state.fetch_workload(&orig_dst.ip()).await?;
        
        // 3. 提取或查找密钥
        let local_addr = stream.local_addr()?;
        let remote_addr = SocketAddr::new(workload.workload_ip, orig_dst.port());
        let keys = self.key_extractor.extract_keys(
            local_addr,
            remote_addr,
            true, // is_client
        ).await?;
        
        // 4. 配置 kTLS
        let mut ktls_conn = KtlsConnection::new(stream, KtlsMode::Both)?;
        ktls_conn.configure_ktls(keys).await?;
        
        // 5. 连接已建立，socket 四元组保持不变
        // 数据传输由内核 kTLS 处理
        info!("kTLS connection established: {} -> {}", local_addr, remote_addr);
        
        Ok(())
    }
}
```

### 2.5 修改 Inbound 处理

**文件**: `src/proxy/inbound.rs`

**当前代码** (第 82-150 行):
```rust
pub async fn run(self) {
    let acceptor = InboundCertProvider { ... };
    let accept = async move |drain, force_shutdown| {
        loop {
            let (raw_socket, src) = self.listener.accept().await?;
            // ... TLS 握手
            let tls = acceptor.accept(raw_socket).await?;
            // ... H2 处理
            h2::server::serve_connection(...).await?;
        }
    };
}
```

**需要修改为**:
```rust
pub async fn run(self) {
    let accept = async move |drain, force_shutdown| {
        loop {
            let (raw_socket, src) = self.listener.accept().await?;
            
            // 检查是否启用 kTLS
            if self.pi.cfg.ktls.enabled && self.pi.cfg.ktls.inbound_enabled {
                // kTLS 路径
                let ktls_handler = KtlsInboundHandler::new(
                    self.pi.clone(),
                    self.pi.key_extractor.as_ref().unwrap().clone(),
                );
                ktls_handler.handle(raw_socket, src).await?;
            } else {
                // 保留原有 HBONE/H2 路径
                let acceptor = InboundCertProvider { ... };
                let tls = acceptor.accept(raw_socket).await?;
                // ... 现有 H2 处理
            }
        }
    };
}
```

### 2.6 创建 KtlsInboundHandler

**文件**: `src/proxy/inbound_ktls.rs` (新文件)

```rust
pub struct KtlsInboundHandler {
    pi: Arc<ProxyInputs>,
    key_extractor: Arc<KeyExtractor>,
}

impl KtlsInboundHandler {
    pub async fn handle(
        &self,
        stream: TcpStream,
        orig_src: SocketAddr,
    ) -> Result<(), Error> {
        // 1. 获取本地地址
        let local_addr = stream.local_addr()?;
        
        // 2. 提取或查找密钥
        let keys = self.key_extractor.extract_keys(
            local_addr,
            orig_src,
            false, // is_server
        ).await?;
        
        // 3. 配置 kTLS
        let mut ktls_conn = KtlsConnection::new(stream, KtlsMode::Both)?;
        ktls_conn.configure_ktls(keys).await?;
        
        // 4. 验证 RBAC（从密钥提取对端身份）
        // TODO: 需要从连接中提取身份信息
        
        // 5. 连接到目标 Pod
        let dest_workload = self.pi.state.fetch_workload(&local_addr.ip()).await?;
        let pod_addr = SocketAddr::new(dest_workload.workload_ip, local_addr.port());
        let mut pod_stream = TcpStream::connect(pod_addr).await?;
        
        // 6. 双向拷贝
        copy_bidirectional(
            &mut ktls_conn.into_stream(),
            &mut pod_stream,
        ).await?;
        
        Ok(())
    }
}
```

## 3. 配置集成

### 3.1 更新 Config 结构

**文件**: `src/config.rs`

```rust
pub struct Config {
    // ... 现有字段
    
    /// kTLS configuration
    pub ktls: KtlsConfig,
}

impl Config {
    pub fn construct_ktls(&self) -> Result<Option<Arc<KeyManager>>, Box<dyn std::error::Error>> {
        if !self.ktls.enabled {
            return Ok(None);
        }
        
        let key_manager = KeyManager::new();
        
        // 如果配置了密钥文件，加载预共享密钥
        if let Some(ref path) = self.ktls.key_config_path {
            key_manager.load_from_file(path).await?;
        }
        
        Ok(Some(Arc::new(key_manager)))
    }
}
```

### 3.2 配置文件示例

```yaml
# config.yaml
ktls:
  enabled: true
  direct_socket_mode: true
  preserve_source_port: true
  inbound_enabled: true
  outbound_enabled: true
  key_config_path: /etc/ztunnel/ktls-keys.json
  cipher_suites:
    - Aes256Gcm
    - Aes128Gcm
```

## 4. 测试方案

### 4.1 密钥生成脚本

**文件**: `scripts/generate-ktls-keys.sh`

```bash
#!/bin/bash
# 生成 kTLS 测试密钥

# 生成随机密钥（32字节 AES-256）
TX_KEY=$(openssl rand -hex 32)
TX_IV=$(openssl rand -hex 12)
RX_KEY=$(openssl rand -hex 32)
RX_IV=$(openssl rand -hex 12)

# 输出 JSON 配置
cat > ktls-keys.json << EOF
[
  {
    "connection_id": {
      "src_addr": "$1",
      "dst_addr": "$2"
    },
    "tx_key": "$TX_KEY",
    "tx_iv": "$TX_IV",
    "rx_key": "$RX_KEY",
    "rx_iv": "$RX_IV",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  }
]
EOF

echo "Generated ktls-keys.json for $1 -> $2"
```

### 4.2 测试环境搭建

**文件**: `scripts/setup-ktls-test.sh`

```bash
#!/bin/bash
set -e

# 创建网络命名空间
ip netns add pod1
ip netns add pod2

# 创建 veth 对
ip link add veth1 type veth peer name veth1-br
ip link add veth2 type veth peer name veth2-br

# 移动到命名空间
ip link set veth1 netns pod1
ip link set veth2 netns pod2

# 配置 IP
ip netns exec pod1 ip addr add 1.2.3.4/24 dev veth1
ip netns exec pod2 ip addr add 10.0.0.2/24 dev veth2

# 启动接口
ip netns exec pod1 ip link set veth1 up
ip netns exec pod2 ip link set veth2 up
ip netns exec pod1 ip link set lo up
ip netns exec pod2 ip link set lo up

echo "Test environment ready"
```

### 4.3 运行测试

```bash
# 1. 生成密钥
./scripts/generate-ktls-keys.sh "1.2.3.4:12345" "10.0.0.2:8080"

# 2. 在 Node X 和 Node Y 部署密钥
cp ktls-keys.json /etc/ztunnel/ktls-keys.json

# 3. 启动 Ztunnel
RUST_LOG=debug cargo run -- run --config-file test-config.yaml

# 4. 验证连接
# 在 pod2 启动服务器
ip netns exec pod2 nc -l 8080 &

# 在 pod1 发起连接
echo "Hello kTLS" | ip netns exec pod1 nc 10.0.0.2 8080

# 5. 验证四元组
tcpdump -i any -n 'port 8080'
# 应该看到: 1.2.3.4:12345 -> 10.0.0.2:8080

# 6. 验证 kTLS socket
cat /proc/net/tls
```

## 5. 验证清单

### 5.1 代码编译
- [ ] `cargo check` 通过
- [ ] `cargo test --lib ktls` 通过
- [ ] 无编译警告

### 5.2 功能验证
- [ ] kTLS 初始化成功
- [ ] 密钥加载成功
- [ ] Outbound 连接建立
- [ ] Inbound 连接接收
- [ ] 数据正确传输

### 5.3 网络验证
- [ ] tcpdump 可见真实四元组
- [ ] 数据包加密（看不到明文）
- [ ] `/proc/net/tls` 显示 kTLS 连接

### 5.4 性能验证
- [ ] 吞吐量符合预期
- [ ] 延迟在可接受范围
- [ ] CPU 使用率正常

## 6. 已知限制

### 6.1 当前实施限制

1. **需要预共享密钥**: 无法自动从 TLS 握手提取密钥
2. **Linux only**: 仅支持 Linux 平台
3. **需要 root 权限**: kTLS 配置需要 CAP_NET_ADMIN
4. **固定加密套件**: 仅支持 AES-GCM 和 ChaCha20-Poly1305

### 6.2 未来改进

1. **自动密钥提取**: 切换到 OpenSSL backend
2. **动态密钥轮换**: 支持密钥更新
3. **更多加密套件**: 扩展支持范围
4. **性能优化**: 减少上下文切换

## 7. 故障排查

### 7.1 常见问题

**问题 1: kTLS 模块未加载**
```bash
# 解决方案
sudo modprobe tls
```

**问题 2: 密钥未找到**
```bash
# 检查密钥文件
cat /etc/ztunnel/ktls-keys.json

# 检查日志
grep "key" /var/log/ztunnel.log
```

**问题 3: 权限不足**
```bash
# 添加 capability
sudo setcap cap_net_admin=eip ./ztunnel
```

### 7.2 调试命令

```bash
# 查看 kTLS 连接
cat /proc/net/tls

# 查看 socket 详情
ss -tiepn | grep kTLS

# 抓包分析
tcpdump -i any -n -X 'port 8080' -w /tmp/ktls.pcap
```

## 8. 文档更新

完成实施后，需要更新以下文档：
- [ ] README-ktls.md - 使用说明
- [ ] implementation-status-zh.md - 更新进度
- [ ] ktls-implementation-details-zh.md - 补充实际实施细节

## 9. 总结

本文档提供了完整的 kTLS 集成方案，包括：
- 详细的代码改造点
- 配置和测试方案
- 验证和故障排查方法

关键步骤：
1. ✅ 创建密钥提取模块
2. ⏳ 修改 outbound/inbound 路径
3. ⏳ 集成测试
4. ⏳ 性能验证

**下一步**: 实施 outbound_ktls.rs 和 inbound_ktls.rs 模块。
