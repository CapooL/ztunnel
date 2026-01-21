# kTLS 实现状态报告

**最后更新**: 2026-01-21  
**当前阶段**: 基础设施完成，核心集成待实现

## 📊 完成度概览

### 已完成 ✅ (约40%)

#### 1. kTLS 核心模块 (`src/ktls/`)
- ✅ **模块入口** (`ktls.rs`) - 支持检测、初始化、错误类型
- ✅ **配置管理** (`config.rs`) - KtlsConfig、加密套件、验证逻辑
- ✅ **密钥管理** (`key_manager.rs`) - KeyMaterial、TlsKeys、KeyManager
- ✅ **连接管理** (`connection.rs`) - KtlsConnection、KtlsMode
- ✅ **Linux实现** (`linux.rs`) - setsockopt封装、AES-GCM/ChaCha20支持

#### 2. 依赖和构建
- ✅ 添加 `hex = "0.4"` 依赖
- ✅ 更新 Cargo.toml 和 Cargo.lock
- ✅ 导出 ktls 模块到 `src/lib.rs`
- ✅ 代码编译通过

#### 3. 文档
- ✅ **现有架构分析** - HBONE流程、三个socket、源端口问题
- ✅ **实现细节文档** - 技术方案、改造路线图、交互流程
- ✅ **测试方案文档** - 环境搭建、测试脚本、验证方法
- ✅ **项目总结文档** - 价值说明、已完成/待完成工作
- ✅ **README** - 快速开始、核心要点

### 未完成 ❌ (约60%)

#### 1. 关键集成工作 (最重要！)
- ❌ **outbound.rs 改造** - 创建直连socket (fd4)
  - 当前: 仍调用 `pool.get_or_create()` 创建HBONE连接
  - 需要: 在fd1上进行TLS握手，配置kTLS
  
- ❌ **inbound.rs 改造** - 接收kTLS连接
  - 当前: 仍解析HBONE CONNECT请求
  - 需要: 接收直连socket，配置kTLS RX

#### 2. 密钥提取机制 (技术难点！)
- ❌ **从rustls提取TLS密钥**
  - 问题: rustls默认不暴露内部密钥
  - 可能方案:
    1. 使用rustls KeyLog trait (如果支持)
    2. Fork rustls添加密钥导出API
    3. 切换到OpenSSL backend (更容易)
    4. 使用BoringSSL backend

#### 3. 测试实施
- ❌ 单元测试实施
- ❌ 集成测试实施
- ❌ 性能基准测试
- ❌ 端到端验证

#### 4. 生产就绪
- ❌ 错误处理完善
- ❌ 日志和监控
- ❌ 配置验证
- ❌ 文档完善（rustdoc）

## 🔍 当前架构状态

### Pod1 → Pod2 流量路径 (当前 HBONE)

```
Pod1 (1.2.3.4:12345)
    ↓ [fd1] TCP明文，被iptables劫持
Ztunnel X Outbound.handle_outbound()
    ↓ 调用 pool.get_or_create(workload_key)
    ↓ 创建新TCP连接 (freebind)
    ↓ [fd2] 源: 1.2.3.4:新端口 -> 目标: Ztunnel Y:15008
    ↓ mTLS握手 + HTTP/2 CONNECT
Ztunnel Y Inbound.serve_h2_request()
    ↓ 解析CONNECT请求
    ↓ [fd3] 连接到Pod2
Pod2 (10.0.0.2:8080)

问题: 网络只能看到 1.2.3.4:新端口 -> 10.0.0.5:15008
```

### 目标架构 (kTLS - 待实现)

```
Pod1 (1.2.3.4:12345)
    ↓ [fd1] TCP明文，被iptables劫持
Ztunnel X (需要新代码!)
    ↓ 在fd1上TLS握手
    ↓ 提取密钥: extract_keys_from_tls_stream()
    ↓ 配置kTLS: setsockopt(SOL_TLS, TLS_TX)
    ↓ [fd4=fd1] 内核加密，四元组: 1.2.3.4:12345 -> 10.0.0.2:8080
Ztunnel Y (需要新代码!)
    ↓ 接收连接，配置kTLS RX
    ↓ [fd3] 连接到Pod2
Pod2 (10.0.0.2:8080)

优势: 网络可见真实四元组 1.2.3.4:12345 -> 10.0.0.2:8080 ✅
```

## 📝 代码修改清单

### 需要修改的文件

#### 1. `src/proxy/outbound.rs` (关键！)

**当前代码** (第99-120行附近):
```rust
let mut oc = OutboundConnection {
    pi: self.pi.clone(),
    id: TraceParent::new(),
};

// ... 

let hbone_conn = pool.get_or_create(workload_key).await?;
let upgraded = hbone_conn.send_request(connect_req).await?;
copy_bidirectional(&mut stream, &mut upgraded).await?;
```

**需要改为** (伪代码):
```rust
if self.pi.cfg.ktls.enabled {
    // kTLS路径
    let cert = self.pi.local_workload.fetch_certificate().await?;
    let connector = cert.outbound_connector(workload.identity())?;
    let tls_stream = connector.connect(stream).await?;
    
    // ⚠️ 关键: 提取密钥 (需要实现!)
    let keys = extract_keys_from_tls_stream(&tls_stream)?;
    
    let mut ktls_conn = KtlsConnection::new(
        tls_stream.into_inner(),
        KtlsMode::Both
    )?;
    ktls_conn.configure_ktls(keys).await?;
    
    // 现在socket已配置kTLS，可以直接使用
} else {
    // 保留原有HBONE路径
    let hbone_conn = pool.get_or_create(workload_key).await?;
    // ...
}
```

#### 2. `src/proxy/inbound.rs` (关键！)

**当前代码** (serve_h2_request函数):
```rust
async fn serve_h2_request(...) {
    let hbone_addr = request_parts.uri.authority().unwrap();
    // 解析HBONE CONNECT请求
    // ...
}
```

**需要改为**:
```rust
async fn handle_inbound_ktls(...) {
    let (stream, orig_src) = listener.accept().await?;
    
    let cert = local_workload.fetch_certificate().await?;
    let acceptor = cert.inbound_acceptor()?;
    let tls_stream = acceptor.accept(stream).await?;
    
    // ⚠️ 关键: 提取密钥
    let keys = extract_keys_from_tls_stream(&tls_stream)?;
    
    let mut ktls_conn = KtlsConnection::new(
        tls_stream.into_inner(),
        KtlsMode::Both
    )?;
    ktls_conn.configure_ktls(keys).await?;
    
    // 验证RBAC
    let peer_identity = extract_peer_identity(&tls_stream)?;
    assert_rbac(&peer_identity, &orig_dst)?;
    
    // 连接到Pod2
    let mut pod_stream = TcpStream::connect(pod_addr).await?;
    copy_bidirectional(&mut ktls_conn.into_stream(), &mut pod_stream).await?;
}
```

#### 3. 密钥提取函数 (需要新建！)

**位置**: `src/ktls/key_extraction.rs` (新文件)

```rust
use tokio_rustls::TlsStream;

pub fn extract_keys_from_tls_stream(
    tls_stream: &TlsStream<TcpStream>
) -> Result<TlsKeys> {
    // ⚠️ 这是最大挑战！
    // rustls默认不暴露密钥
    
    // 方案A: 使用KeyLog (如果rustls支持)
    // 方案B: 使用OpenSSL backend
    // 方案C: Fork rustls
    
    todo!("实现密钥提取")
}
```

## 🔧 技术难点分析

### 难点1: rustls密钥提取 ⚠️

**问题**: rustls出于安全考虑，不直接暴露TLS会话密钥。

**可能的解决方案**:

1. **使用rustls的KeyLog trait**
```rust
struct KeyLogger {
    keys: Arc<Mutex<HashMap<ConnectionId, TlsKeys>>>,
}

impl rustls::KeyLog for KeyLogger {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        // 从CLIENT_TRAFFIC_SECRET和SERVER_TRAFFIC_SECRET提取
    }
}
```

2. **切换到OpenSSL backend** (推荐)
```rust
#[cfg(feature = "tls-openssl")]
use openssl::ssl::SslStream;

fn extract_keys_openssl(conn: &SslStream) -> Result<TlsKeys> {
    // OpenSSL提供SSL_export_keying_material API
    // 更容易提取密钥
}
```

3. **Fork rustls**
- 添加`dangerous_export_keys()` API
- 仅在`#[cfg(feature = "ktls")]`时暴露

### 难点2: 端口保留

**解决方案**: 不创建新socket，直接在fd1上升级。

```rust
// ❌ 错误: 会分配新端口
let new_stream = TcpStream::connect(dst).await?;

// ✅ 正确: 在原socket上升级
let tls_stream = connector.connect(existing_stream).await?;
```

### 难点3: iptables规则

**当前**: REDIRECT改变目标地址  
**需要**: 使用TPROXY或保留SO_ORIGINAL_DST

```rust
use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
let orig_dst = getsockopt(fd, OriginalDst)?;
```

## 🧪 测试策略

### 阶段1: 单元测试 (可独立完成)
```bash
cargo test --lib ktls
```
- 测试密钥管理
- 测试配置验证
- 测试kTLS配置接口

### 阶段2: 集成测试 (需要完成核心集成)
```bash
./scripts/test-socket-tuple.sh
./scripts/test-encryption.sh
```
- 验证四元组
- 验证加密
- 验证kTLS socket存在

### 阶段3: 性能测试
```bash
./scripts/test-performance.sh
```
- HBONE vs kTLS对比

**注意**: Ztunnel可以独立测试，不需要完整的Istio环境。使用network namespace模拟Pod网络。

## 📅 实施时间线

### 立即任务 (1-2周)
1. **研究密钥提取方案** 
   - 测试rustls KeyLog
   - 评估OpenSSL backend
2. **实现密钥提取函数**
3. **修改outbound.rs** - 第一个工作原型

### 短期任务 (2-3周)
1. **修改inbound.rs**
2. **集成测试**
3. **基础功能验证**

### 中期任务 (1个月)
1. **性能测试**
2. **错误处理完善**
3. **文档补充**

### 长期任务 (2个月)
1. **生产环境准备**
2. **监控和告警**
3. **正式发布**

## 🎯 下一步行动

### 建议的实施顺序

1. **确定密钥提取方案** (最关键)
   - 调研rustls是否支持KeyLog
   - 如果不支持，切换到OpenSSL backend
   
2. **实现概念验证**
   - 创建最小可行的outbound修改
   - 验证能否提取密钥并配置kTLS
   
3. **完整集成**
   - 完成outbound和inbound修改
   - 添加错误处理
   
4. **测试验证**
   - 运行集成测试
   - 验证四元组可见性
   
5. **性能优化**
   - 基准测试
   - 性能调优

## 📞 需要决策的问题

1. **是否切换到OpenSSL backend？**
   - 优点: 更容易提取密钥
   - 缺点: 需要修改TLS配置

2. **是否支持HBONE和kTLS共存？**
   - 优点: 渐进式迁移
   - 缺点: 维护两套代码

3. **测试环境如何搭建？**
   - 使用network namespace？
   - 使用完整的K8s环境？

## 📄 相关文档

- [现有架构分析](./ztunnel-current-architecture-zh.md)
- [实现细节](./ktls-implementation-details-zh.md)
- [测试方案](./ktls-test-plan-zh.md)
- [项目总结](./ktls-project-summary-zh.md)
- [README](../README-ktls.md)

---

**结论**: kTLS基础设施已完成40%，但最关键的集成工作（outbound/inbound改造和密钥提取）尚未开始。建议首先解决密钥提取技术难点，然后逐步完成集成。
