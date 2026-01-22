# kTLS 完整实施路线图

**日期**: 2026-01-21  
**状态**: 基础设施完成，准备集成阶段

## 执行摘要

本文档提供 kTLS 完整集成的详细实施步骤。基础设施（密钥管理、Linux kTLS 支持）已完成，现在需要集成到 Ztunnel 的数据路径中。

## 已完成的基础工作 ✅

### 1. kTLS 核心模块
- ✅ `src/ktls/config.rs` - 配置管理
- ✅ `src/ktls/key_manager.rs` - 密钥存储和管理
- ✅ `src/ktls/connection.rs` - kTLS 连接封装
- ✅ `src/ktls/linux.rs` - Linux kTLS 系统调用
- ✅ `src/ktls/key_extraction.rs` - 密钥提取接口

### 2. 技术调研
- ✅ 确认 rustls 支持 `dangerous_extract_secrets()` API
- ✅ 验证 Linux kTLS 支持的加密套件
- ✅ 分析现有 HBONE 架构

### 3. 文档
- ✅ 8 份完整的中文技术文档
- ✅ 测试方案和验证脚本
- ✅ 代码改造详细说明

## 待实施的集成工作

### 第一阶段：密钥提取增强（1-2天）

#### 1.1 更新 key_extraction.rs

**目标**: 添加对 rustls `dangerous_extract_secrets()` 的支持

**修改点**:
```rust
// src/ktls/key_extraction.rs

use rustls::Connection;

pub enum KeyExtractionStrategy {
    /// 从 rustls Connection 自动提取密钥 ⭐ 新增
    RustlsExtract,
    
    /// 预共享密钥（备选）
    PreShared(Arc<KeyManager>),
    
    /// Mock（测试）
    #[cfg(test)]
    Mock,
}

impl KeyExtractor {
    /// 从 rustls Connection 提取密钥
    pub fn extract_from_rustls_connection(
        &self,
        connection: Connection,
    ) -> Result<TlsKeys> {
        // 调用 rustls API
        let secrets = connection.dangerous_extract_secrets()
            .map_err(|e| KtlsError::KeyExtraction(format!("rustls extract failed: {}", e)))?;
        
        // 转换为 TlsKeys
        let tx_keys = convert_traffic_secrets(&secrets.tx)?;
        let rx_keys = convert_traffic_secrets(&secrets.rx)?;
        
        Ok(TlsKeys { tx: tx_keys, rx: rx_keys })
    }
}

fn convert_traffic_secrets(
    secrets: &(u64, rustls::ConnectionTrafficSecrets),
) -> Result<KeyMaterial> {
    let (seq, traffic_secrets) = secrets;
    
    match traffic_secrets {
        rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            Ok(KeyMaterial {
                tls_version: 0x0304,  // TLS 1.3
                cipher_suite: 0x1301,  // TLS_AES_128_GCM_SHA256
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: *seq,
            })
        }
        rustls::ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            Ok(KeyMaterial {
                tls_version: 0x0304,
                cipher_suite: 0x1302,  // TLS_AES_256_GCM_SHA384
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: *seq,
            })
        }
        rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            Ok(KeyMaterial {
                tls_version: 0x0304,
                cipher_suite: 0x1303,  // TLS_CHACHA20_POLY1305_SHA256
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: *seq,
            })
        }
    }
}
```

**测试**:
```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_rustls_extraction() {
        // 创建测试 TLS 连接
        // 提取密钥
        // 验证密钥格式
    }
}
```

**验证命令**:
```bash
cargo test --lib ktls::key_extraction
```

---

### 第二阶段：Outbound 集成（3-5天）

#### 2.1 创建 outbound_ktls 模块

**文件**: `src/proxy/outbound_ktls.rs` (新文件)

```rust
// Copyright Istio Authors
// Licensed under the Apache License, Version 2.0

//! kTLS-based outbound connection handler

use crate::ktls::{KeyExtractor, KtlsConnection, KtlsMode};
use crate::proxy::{Error, ProxyInputs};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

pub struct KtlsOutboundHandler {
    pi: Arc<ProxyInputs>,
    key_extractor: Arc<KeyExtractor>,
}

impl KtlsOutboundHandler {
    pub fn new(pi: Arc<ProxyInputs>, key_extractor: Arc<KeyExtractor>) -> Self {
        Self { pi, key_extractor }
    }

    /// 处理 outbound 连接，使用 kTLS 替代 HBONE
    pub async fn handle(&self, mut stream: TcpStream) -> Result<(), Error> {
        // 1. 获取原始目标地址（通过 SO_ORIGINAL_DST）
        let orig_dst = socket::orig_dst_addr(&stream)?;
        debug!("kTLS outbound: original destination: {}", orig_dst);

        // 2. 查询目标工作负载
        let workload = self.pi.state
            .fetch_workload(&orig_dst.ip())
            .await
            .ok_or_else(|| Error::UnknownDestination(orig_dst))?;

        // 3. 获取本地地址（用于保留源端口）
        let local_addr = stream.local_addr()?;
        debug!("kTLS outbound: local address: {}", local_addr);

        // 4. 建立到目标的 TLS 连接
        let remote_addr = SocketAddr::new(workload.workload_ip, orig_dst.port());
        debug!("kTLS outbound: connecting to: {}", remote_addr);

        // 创建到目标的新连接
        let target_stream = TcpStream::connect(remote_addr).await?;
        
        // 5. 执行 TLS 握手
        let tls_connector = TlsConnector::from(Arc::new(
            self.pi.cert_manager.client_config()
        ));
        let domain = workload.identity.as_str();
        let tls_stream = tls_connector.connect(domain.try_into()?, target_stream).await?;

        // 6. 从 TLS 连接提取密钥
        let (target_tcp, tls_connection) = tls_stream.into_inner();
        let keys = self.key_extractor.extract_from_rustls_connection(tls_connection)?;

        // 7. 配置 kTLS
        let mut ktls_conn = KtlsConnection::new(target_tcp, KtlsMode::Both)?;
        ktls_conn.configure_ktls(keys).await?;

        info!(
            "kTLS outbound connection established: {} -> {}",
            local_addr, remote_addr
        );

        // 8. 双向数据拷贝
        let (mut client_read, mut client_write) = stream.into_split();
        let (mut server_read, mut server_write) = ktls_conn.into_split();

        let client_to_server = tokio::io::copy(&mut client_read, &mut server_write);
        let server_to_client = tokio::io::copy(&mut server_read, &mut client_write);

        tokio::select! {
            res = client_to_server => {
                debug!("Client to server copy finished: {:?}", res);
            }
            res = server_to_client => {
                debug!("Server to client copy finished: {:?}", res);
            }
        }

        Ok(())
    }
}
```

#### 2.2 修改 src/proxy/outbound.rs

**添加条件分支**:
```rust
// 在 Outbound::run() 中添加

// 检查是否启用 kTLS
if self.pi.cfg.ktls.enabled && self.pi.cfg.ktls.outbound_enabled {
    if let Some(ref key_extractor) = self.pi.key_extractor {
        // 使用 kTLS 路径
        let ktls_handler = KtlsOutboundHandler::new(
            self.pi.clone(),
            key_extractor.clone(),
        );
        return ktls_handler.handle(stream).await;
    }
}

// 否则使用原有 HBONE 路径
let mut oc = OutboundConnection {
    pi: self.pi.clone(),
    id: TraceParent::new(),
    pool: pool.clone(),
    hbone_port: self.pi.cfg.inbound_addr.port(),
};
oc.proxy(stream).await
```

#### 2.3 更新 mod.rs 导出

```rust
// src/proxy/mod.rs
#[cfg(target_os = "linux")]
mod outbound_ktls;
```

---

### 第三阶段：Inbound 集成（3-5天）

#### 3.1 创建 inbound_ktls 模块

**文件**: `src/proxy/inbound_ktls.rs` (新文件)

```rust
// Copyright Istio Authors

//! kTLS-based inbound connection handler

use crate::ktls::{KeyExtractor, KtlsConnection, KtlsMode};
use crate::proxy::{Error, ProxyInputs};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

pub struct KtlsInboundHandler {
    pi: Arc<ProxyInputs>,
    key_extractor: Arc<KeyExtractor>,
}

impl KtlsInboundHandler {
    pub fn new(pi: Arc<ProxyInputs>, key_extractor: Arc<KeyExtractor>) -> Self {
        Self { pi, key_extractor }
    }

    pub async fn handle(
        &self,
        stream: TcpStream,
        orig_src: SocketAddr,
    ) -> Result<(), Error> {
        // 1. 获取本地地址
        let local_addr = stream.local_addr()?;
        debug!("kTLS inbound: from {} to {}", orig_src, local_addr);

        // 2. 执行 TLS 握手（作为服务器）
        let tls_acceptor = TlsAcceptor::from(Arc::new(
            self.pi.cert_manager.server_config()
        ));
        let tls_stream = tls_acceptor.accept(stream).await?;

        // 3. 提取密钥
        let (tcp_stream, tls_connection) = tls_stream.into_inner();
        let keys = self.key_extractor.extract_from_rustls_connection(tls_connection)?;

        // 4. 配置 kTLS
        let mut ktls_conn = KtlsConnection::new(tcp_stream, KtlsMode::Both)?;
        ktls_conn.configure_ktls(keys).await?;

        info!("kTLS inbound connection established: {} -> {}", orig_src, local_addr);

        // 5. 查询目标 Pod
        let dest_workload = self.pi.state
            .fetch_workload(&local_addr.ip())
            .await
            .ok_or_else(|| Error::UnknownDestination(local_addr))?;

        // 6. 连接到目标 Pod
        let pod_addr = SocketAddr::new(dest_workload.workload_ip, local_addr.port());
        let mut pod_stream = TcpStream::connect(pod_addr).await?;

        // 7. 双向拷贝
        let (mut ktls_read, mut ktls_write) = ktls_conn.into_split();
        let (mut pod_read, mut pod_write) = pod_stream.split();

        let ktls_to_pod = tokio::io::copy(&mut ktls_read, &mut pod_write);
        let pod_to_ktls = tokio::io::copy(&mut pod_read, &mut ktls_write);

        tokio::select! {
            res = ktls_to_pod => {
                debug!("kTLS to Pod copy finished: {:?}", res);
            }
            res = pod_to_ktls => {
                debug!("Pod to kTLS copy finished: {:?}", res);
            }
        }

        Ok(())
    }
}
```

#### 3.2 修改 src/proxy/inbound.rs

```rust
// 在 Inbound::run() 中添加

if self.pi.cfg.ktls.enabled && self.pi.cfg.ktls.inbound_enabled {
    if let Some(ref key_extractor) = self.pi.key_extractor {
        let ktls_handler = KtlsInboundHandler::new(
            self.pi.clone(),
            key_extractor.clone(),
        );
        return ktls_handler.handle(raw_socket, src).await;
    }
}

// 否则使用原有 HBONE/H2 路径
```

---

### 第四阶段：配置集成（1天）

#### 4.1 更新 ProxyInputs

```rust
// src/proxy.rs

pub struct ProxyInputs {
    // ... 现有字段
    
    /// kTLS key extractor (if enabled)
    #[cfg(target_os = "linux")]
    pub key_extractor: Option<Arc<KeyExtractor>>,
}
```

#### 4.2 更新配置初始化

```rust
// 在 main.rs 或 config 初始化处

let key_extractor = if config.ktls.enabled {
    Some(Arc::new(KeyExtractor::new(
        KeyExtractionStrategy::RustlsExtract
    )))
} else {
    None
};

let proxy_inputs = ProxyInputs {
    // ... 其他字段
    key_extractor,
};
```

---

### 第五阶段：测试（3-5天）

#### 5.1 单元测试

```bash
# 测试密钥提取
cargo test --lib ktls::key_extraction

# 测试 kTLS 连接
cargo test --lib ktls::connection

# 测试配置
cargo test --lib ktls::config
```

#### 5.2 集成测试脚本

**文件**: `tests/ktls_integration_test.sh`

```bash
#!/bin/bash
set -e

echo "=== kTLS 集成测试 ==="

# 1. 检查 kTLS 支持
if [ ! -f /proc/net/tls ]; then
    echo "错误: 系统不支持 kTLS"
    exit 1
fi

# 2. 创建测试环境
ip netns add pod1
ip netns add pod2

# 3. 配置网络
ip link add veth1 type veth peer name veth1-br
ip link add veth2 type veth peer name veth2-br
ip link set veth1 netns pod1
ip link set veth2 netns pod2

ip netns exec pod1 ip addr add 1.2.3.4/24 dev veth1
ip netns exec pod2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec pod1 ip link set veth1 up
ip netns exec pod2 ip link set veth2 up

# 4. 启动 ztunnel
cargo build --release --features tls-aws-lc
./target/release/ztunnel run --config test-ktls.yaml &
ZTUNNEL_PID=$!

sleep 5

# 5. 启动测试服务器
ip netns exec pod2 nc -l 8080 > /tmp/server_output &
SERVER_PID=$!

# 6. 发送测试数据
echo "Hello kTLS" | ip netns exec pod1 nc 10.0.0.2 8080

# 7. 验证四元组
echo "检查四元组可见性..."
tcpdump -i any -n 'port 8080' -c 10 > /tmp/tcpdump_output 2>&1 &
TCPDUMP_PID=$!

sleep 2
kill $TCPDUMP_PID 2>/dev/null || true

if grep -q "1.2.3.4.*->.*10.0.0.2.8080" /tmp/tcpdump_output; then
    echo "✓ 四元组可见"
else
    echo "✗ 四元组不可见"
    exit 1
fi

# 8. 验证 kTLS socket
if cat /proc/net/tls | grep -q "8080"; then
    echo "✓ kTLS socket 存在"
else
    echo "✗ kTLS socket 不存在"
    exit 1
fi

# 9. 清理
kill $ZTUNNEL_PID $SERVER_PID 2>/dev/null || true
ip netns del pod1
ip netns del pod2

echo "=== 测试通过 ==="
```

#### 5.3 性能测试

```bash
# 对比 HBONE vs kTLS
./tests/performance_comparison.sh
```

---

### 第六阶段：文档和发布（1-2天）

#### 6.1 创建最终实施报告

**文件**: `docs/ktls-final-implementation-report-zh.md`

包含：
- 完整的代码修改清单
- 测试结果和性能数据
- 已知限制和未来工作
- 使用说明和配置示例

#### 6.2 更新 README

添加 kTLS 使用说明

---

## 实施时间表

| 阶段 | 任务 | 预计时间 | 累计时间 |
|------|------|---------|---------|
| 1 | 密钥提取增强 | 1-2天 | 1-2天 |
| 2 | Outbound 集成 | 3-5天 | 4-7天 |
| 3 | Inbound 集成 | 3-5天 | 7-12天 |
| 4 | 配置集成 | 1天 | 8-13天 |
| 5 | 测试 | 3-5天 | 11-18天 |
| 6 | 文档 | 1-2天 | 12-20天 |

**总计**: 12-20 天（约 2-3 周）

---

## 风险和缓解

### 风险 1: rustls API 版本兼容性
- **影响**: 高
- **概率**: 中
- **缓解**: 提前验证 rustls 0.23 API

### 风险 2: kTLS 内核支持问题
- **影响**: 中
- **概率**: 低
- **缓解**: 保留 HBONE 作为回退

### 风险 3: 性能不达预期
- **影响**: 低
- **概率**: 低
- **缓解**: 性能测试和优化

---

## 验收标准

### 功能验证
- [ ] kTLS 连接成功建立
- [ ] 数据正确传输
- [ ] 四元组在 tcpdump 中可见
- [ ] /proc/net/tls 显示 kTLS 连接

### 性能验证
- [ ] 吞吐量提升 ≥ 20%
- [ ] 延迟降低 ≥ 30%
- [ ] CPU 使用率降低 ≥ 20%

### 兼容性验证
- [ ] HBONE 回退正常工作
- [ ] 非 Linux 平台正常编译
- [ ] 现有测试全部通过

---

## 下一步行动

### 立即开始（今天）
1. 验证 rustls 0.23 API
2. 更新 key_extraction.rs
3. 编写单元测试

### 本周内
1. 实现 outbound_ktls.rs
2. 基础功能测试
3. 修复发现的问题

### 下周
1. 实现 inbound_ktls.rs
2. 完整集成测试
3. 性能测试

---

## 总结

基础设施已就绪，技术路径已明确。使用 rustls 的 `dangerous_extract_secrets()` API 可以实现完全自动化的 kTLS，预计 2-3 周完成完整集成。

**关键优势**:
- ✅ 无需切换 TLS backend
- ✅ 自动密钥提取
- ✅ 真实四元组可见
- ✅ 性能显著提升

**建议**: 按照本路线图分阶段实施，每个阶段完成后进行验证，确保质量。
