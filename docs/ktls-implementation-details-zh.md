# Ztunnel kTLS 改造方案详细文档

## 1. 改造目标

将 Ztunnel 从基于 HBONE (HTTP/2) 的隧道协议改造为基于 Linux 内核 TLS (kTLS) 的直连方案，实现：

1. **真实四元组可见性**: 网络层可审计的 `pod1_ip:pod1_port -> pod2_ip:pod2_port` 连接
2. **保持加密安全**: 使用 kTLS 在内核层面提供 TLS 1.3 加密
3. **性能优化**: 减少用户态-内核态数据拷贝，降低 CPU 开销
4. **灵活配置**: 支持外部系统注入密钥

## 2. 核心技术方案

### 2.1 什么是 kTLS (Kernel TLS)

kTLS 是 Linux 内核提供的 TLS 加速功能，它将 TLS 加密/解密操作从用户态移到内核态执行。

**关键特点**：
- 在用户态完成 TLS 握手（密钥协商、证书验证）
- 将协商好的密钥传递给内核
- 内核透明地处理数据加解密
- Socket 保持原始的四元组信息

**Linux内核接口**：
```c
// 配置 TX (发送端) kTLS
setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info));

// 配置 RX (接收端) kTLS
setsockopt(fd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info));
```

### 2.2 架构对比

#### 当前 HBONE 架构

```
Pod1 (1.2.3.4:12345)
    ↓ [fd1] TCP 明文
Ztunnel X :15001 (Outbound)
    | 1. 创建到 Ztunnel Y 的新 TCP 连接
    | 2. 源 IP 欺骗为 1.2.3.4 (freebind)
    | 3. 源端口由系统新分配 (例如: 45678)
    ↓ [fd2] mTLS + HTTP/2 CONNECT
Ztunnel Y :15008 (Inbound)
    ↓ [fd3] TCP 明文
Pod2 (10.0.0.2:8080)

网络可见: 1.2.3.4:45678 -> 10.0.0.5:15008 (不是真实的 Pod-to-Pod)
```

#### 新的 kTLS 直连架构

```
Pod1 (1.2.3.4:12345)
    ↓ [fd1] TCP 明文 (被劫持)
Ztunnel X :15001 (Outbound Socket Hijacker)
    | 1. 劫持 socket，保留 fd1
    | 2. 进行 TLS 握手（证书验证）
    | 3. 提取 TLS 密钥
    | 4. 配置 kTLS TX
    ↓ [fd4] kTLS 加密 (内核加密)
Ztunnel Y :15001 (Inbound Socket Receiver)
    | 1. 接收连接，保留原始四元组
    | 2. 进行 TLS 握手
    | 3. 提取 TLS 密钥
    | 4. 配置 kTLS RX
    ↓ [fd3] TCP 明文
Pod2 (10.0.0.2:8080)

网络可见: 1.2.3.4:12345 -> 10.0.0.2:8080 (真实的 Pod-to-Pod！)
```

**关键改变**：
- 移除 fd2 (HBONE 连接)
- fd4 = fd1，同一个 socket，不创建新连接
- 四元组完全保留
- 在 socket 上启用 kTLS

## 3. 详细代码改造点

### 3.1 新增模块: `src/ktls/`

#### 3.1.1 `ktls.rs` - 主模块
```rust
// 模块入口
// 功能: 检查 kTLS 支持，初始化子系统

pub fn is_supported() -> bool;
pub fn init() -> Result<()>;
```

#### 3.1.2 `ktls/config.rs` - 配置管理
```rust
pub struct KtlsConfig {
    enabled: bool,                    // 是否启用 kTLS
    key_config_path: Option<PathBuf>, // 密钥配置文件路径
    direct_socket_mode: bool,         // 直连模式 (绕过 HBONE)
    preserve_source_port: bool,       // 保留源端口
    inbound_enabled: bool,            // Inbound 启用
    outbound_enabled: bool,           // Outbound 启用
    cipher_suites: Vec<CipherSuite>,  // 支持的加密套件
}
```

**配置示例**：
```yaml
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

#### 3.1.3 `ktls/key_manager.rs` - 密钥管理
```rust
pub struct KeyMaterial {
    tls_version: u16,      // TLS 1.3 = 0x0304
    cipher_suite: u16,     // 加密套件代码
    key: Vec<u8>,          // 加密密钥
    iv: Vec<u8>,           // 初始化向量
    seq: u64,              // 序列号
}

pub struct TlsKeys {
    tx: KeyMaterial,  // 发送端密钥
    rx: KeyMaterial,  // 接收端密钥
}

pub struct KeyManager {
    // 存储连接ID到密钥的映射
    keys: Arc<RwLock<HashMap<ConnectionId, TlsKeys>>>,
}
```

**外部密钥注入接口**：
```json
// /etc/ztunnel/ktls-keys.json
[
  {
    "connection_id": {
      "src_addr": "1.2.3.4:12345",
      "dst_addr": "10.0.0.2:8080"
    },
    "tx_key": "a1b2c3d4...",  // hex 编码
    "tx_iv": "e5f6g7h8...",
    "rx_key": "i9j0k1l2...",
    "rx_iv": "m3n4o5p6...",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  }
]
```

#### 3.1.4 `ktls/connection.rs` - 连接管理
```rust
pub struct KtlsConnection {
    stream: TcpStream,     // 底层 TCP socket
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    mode: KtlsMode,        // TxOnly / RxOnly / Both
    configured: bool,
}

impl KtlsConnection {
    pub async fn configure_ktls(&mut self, keys: TlsKeys) -> Result<()>;
}
```

#### 3.1.5 `ktls/linux.rs` - Linux 平台实现
```rust
// 配置 kTLS TX
pub fn configure_ktls_tx(stream: &TcpStream, key_material: &KeyMaterial) -> Result<()> {
    let fd = stream.as_raw_fd();
    
    // 构建 crypto_info 结构
    let crypto_info = match cipher_suite {
        AES_128_GCM => build_aes_128_gcm_info(key_material),
        AES_256_GCM => build_aes_256_gcm_info(key_material),
        // ...
    };
    
    // 调用 setsockopt
    unsafe {
        libc::setsockopt(fd, SOL_TLS, TLS_TX, &crypto_info, size);
    }
}
```

### 3.2 改造点: `src/config.rs`

在主配置结构中添加 kTLS 配置：

```rust
pub struct Config {
    // ... 现有字段
    
    /// kTLS configuration
    pub ktls: KtlsConfig,
}
```

### 3.3 改造点: `src/proxy/outbound.rs`

#### 当前流程 (HBONE)
```rust
// outbound.rs: handle_outbound 函数
async fn handle_outbound(...) {
    // 1. 接收来自 Pod 的连接 (fd1)
    let (stream, orig_src) = listener.accept().await?;
    
    // 2. 查询目标工作负载信息
    let workload = state.find_workload(...);
    
    // 3. 从连接池获取或创建 HBONE 连接 (fd2)
    let hbone_conn = pool.get_or_create(workload_key).await?;
    
    // 4. 发送 CONNECT 请求
    let upgraded = hbone_conn.send_request(connect_req).await?;
    
    // 5. 双向拷贝数据
    copy_bidirectional(&mut stream, &mut upgraded).await?;
}
```

#### 新流程 (kTLS 直连)
```rust
// outbound.rs: handle_outbound_ktls 函数
async fn handle_outbound_ktls(...) {
    // 1. 接收来自 Pod 的连接 (fd1)
    let (mut stream, orig_src) = listener.accept().await?;
    
    // 2. 查询目标工作负载信息
    let workload = state.find_workload(...);
    let dest_addr = workload.socket_addr();  // 10.0.0.2:8080
    
    // !! 关键: 不创建新连接，直接在 fd1 上操作 !!
    
    // 3. 获取证书和创建 TLS 连接器
    let cert = local_workload.fetch_certificate().await?;
    let connector = cert.outbound_connector(workload.identity())?;
    
    // 4. 在 fd1 上进行 TLS 握手
    let tls_stream = connector.connect(stream).await?;
    
    // 5. 提取 TLS 密钥
    let keys = extract_keys_from_tls_stream(&tls_stream)?;
    
    // 6. 创建 kTLS 连接并配置密钥
    let mut ktls_conn = KtlsConnection::new(
        tls_stream.into_inner(),  // 取出底层 TCP stream
        KtlsMode::Both
    )?;
    ktls_conn.configure_ktls(keys).await?;
    
    // 7. 现在 ktls_conn 就是加密的直连 socket!
    // 内核会自动加解密，socket 四元组保持不变
    
    // 8. 直接使用 ktls_conn 进行数据传输
    // 不需要 copy_bidirectional，因为这是端到端的连接
    // 只需要将控制权交还给应用层或转发到目标 Pod
}
```

**核心改动**：
- 不调用 `pool.get_or_create()` (不需要 HBONE 连接池)
- 不发送 HTTP/2 CONNECT 请求
- 在原始 socket (fd1) 上进行 TLS 握手
- 配置 kTLS 后，socket 变成加密的直连

### 3.4 改造点: `src/proxy/inbound.rs`

#### 当前流程 (HBONE)
```rust
// inbound.rs: serve_h2_request 函数
async fn serve_h2_request(...) {
    // 1. 接收 HBONE CONNECT 请求
    let hbone_addr = parse_connect_uri(request);
    
    // 2. 验证 RBAC
    assert_rbac(&connection, &hbone_addr)?;
    
    // 3. 建立到目标 Pod 的连接 (fd3)
    let mut outbound = TcpStream::connect(pod_addr).await?;
    
    // 4. 返回 200 OK
    send_response(StatusCode::OK)?;
    
    // 5. 双向拷贝
    copy_bidirectional(&mut inbound_stream, &mut outbound).await?;
}
```

#### 新流程 (kTLS 直连)
```rust
// inbound.rs: handle_inbound_ktls 函数
async fn handle_inbound_ktls(...) {
    // 1. 接收来自 Ztunnel X 的连接 (已经是 fd4 了)
    let (stream, orig_src) = listener.accept().await?;
    
    // 2. 获取本地工作负载证书
    let cert = local_workload.fetch_certificate().await?;
    let acceptor = cert.inbound_acceptor()?;
    
    // 3. 进行 TLS 握手 (验证对方身份)
    let tls_stream = acceptor.accept(stream).await?;
    
    // 4. 提取 TLS 密钥
    let keys = extract_keys_from_tls_stream(&tls_stream)?;
    
    // 5. 验证 RBAC (使用对方的身份证书)
    let peer_identity = extract_peer_identity(&tls_stream)?;
    assert_rbac(&peer_identity, &orig_dst)?;
    
    // 6. 创建 kTLS 连接并配置密钥
    let mut ktls_conn = KtlsConnection::new(
        tls_stream.into_inner(),
        KtlsMode::Both
    )?;
    ktls_conn.configure_ktls(keys).await?;
    
    // 7. 建立到目标 Pod 的连接 (fd3)
    let mut pod_stream = TcpStream::connect(pod_addr).await?;
    
    // 8. 双向拷贝 (kTLS conn ↔ Pod)
    copy_bidirectional(
        &mut ktls_conn.into_stream(),
        &mut pod_stream
    ).await?;
}
```

**核心改动**：
- 不监听 15008 端口的 HBONE 连接
- 监听 15001 端口接收直连的 kTLS 连接
- 不解析 CONNECT 请求，直接从 socket 属性获取目标地址
- 配置 kTLS 后进行数据转发

### 3.5 TLS 密钥提取

这是 kTLS 方案的关键技术点。需要从 rustls 的 TLS 会话中提取密钥。

```rust
// 概念代码 (实际实现取决于 rustls 版本)
fn extract_keys_from_tls_stream(
    tls_stream: &tokio_rustls::TlsStream<TcpStream>
) -> Result<TlsKeys> {
    // 获取 TLS 会话信息
    let session = tls_stream.get_ref().1; // rustls::ClientConnection or ServerConnection
    
    // TLS 1.3 密钥提取
    // 注意: rustls 可能不直接暴露密钥，需要使用特殊 API 或 fork
    let (cipher_suite, tx_key, tx_iv, rx_key, rx_iv, tx_seq, rx_seq) = 
        extract_tls13_traffic_secrets(session)?;
    
    let keys = TlsKeys {
        tx: KeyMaterial::new(0x0304, cipher_suite, tx_key, tx_iv),
        rx: KeyMaterial::new(0x0304, cipher_suite, rx_key, rx_iv),
    };
    
    keys.tx.seq = tx_seq;
    keys.rx.seq = rx_seq;
    
    Ok(keys)
}
```

**挑战**：
- rustls 默认不暴露内部密钥（安全考虑）
- 可能需要使用 rustls 的 `dangerous_configuration` 或自定义 fork
- 或者使用 `SSLKEYLOGFILE` 机制（调试用）

**推荐方案**：
1. 使用 rustls 的 key export API（如果存在）
2. 或者实现自定义的 `KeyLog` trait
3. 或者使用 openssl backend (更容易提取密钥)

## 4. Socket 劫持和端口保留

### 4.1 保留源端口的挑战

在当前 HBONE 方案中，fd2 的源端口是系统新分配的。要保留 fd1 的源端口 (12345)，需要：

#### 方案 1: 不创建新 socket (推荐)
```rust
// 直接在 fd1 上进行 TLS 握手和 kTLS 配置
// 优点: 端口自然保留
// 缺点: 需要修改路由和连接流程
```

#### 方案 2: Socket 迁移
```rust
// 使用 SO_REUSEPORT 和 bind() 到相同端口
// 1. 获取 fd1 的本地端口
let orig_port = stream.local_addr()?.port();

// 2. 创建新 socket
let new_socket = TcpSocket::new_v4()?;
new_socket.set_reuseport(true)?;
new_socket.bind(SocketAddr::new(pod1_ip, orig_port))?;

// 3. 连接到目标
new_socket.connect(dest_addr).await?;
```

**推荐**: 使用方案 1，不创建新连接。

### 4.2 iptables 规则调整

当前 iptables 规则将流量重定向到 15001：
```bash
iptables -t nat -A OUTPUT -p tcp \
    -j REDIRECT --to-port 15001
```

kTLS 模式下，需要调整：
```bash
# 对于 kTLS 直连模式，不需要 REDIRECT
# 而是使用 TPROXY 进行透明代理

iptables -t mangle -A PREROUTING -p tcp \
    -j TPROXY --on-port 15001 --tproxy-mark 0x1/0x1
```

## 5. 完整交互流程

### 5.1 Outbound 流程 (Pod1 → Pod2)

```
时刻 T0: Pod1 应用发起连接
    App: connect(10.0.0.2:8080)
    Kernel: 创建 socket fd_app
    四元组: 1.2.3.4:12345 → 10.0.0.2:8080

时刻 T1: iptables 劫持
    iptables: 匹配 OUTPUT 规则
    目标改写: 10.0.0.2:8080 → 127.0.0.1:15001
    但保留原始目标信息 (SO_ORIGINAL_DST)

时刻 T2: Ztunnel Outbound 接收连接
    Outbound: accept() → fd1
    获取原始目标: getsockopt(SO_ORIGINAL_DST) → 10.0.0.2:8080
    
时刻 T3: 查询目标工作负载
    查询 State: 10.0.0.2 → Workload(identity, certificates)

时刻 T4: TLS 握手 (用户态)
    获取本地证书: local_workload.fetch_certificate()
    创建 TLS 连接器: cert.outbound_connector(dst_identity)
    在 fd1 上握手: tls_stream = connector.connect(fd1)
    验证对方证书 SAN 匹配 dst_identity

时刻 T5: 提取 TLS 密钥
    从 tls_stream 提取:
        - Cipher suite: TLS_AES_256_GCM_SHA384
        - TX key: [32 bytes]
        - TX IV: [12 bytes]
        - RX key: [32 bytes]
        - RX IV: [12 bytes]
        - Sequence numbers

时刻 T6: 配置 kTLS
    获取 fd1 的 raw fd
    调用 setsockopt(fd, SOL_TLS, TLS_TX, &tx_crypto_info)
    调用 setsockopt(fd, SOL_TLS, TLS_RX, &rx_crypto_info)
    fd1 现在是 kTLS socket

时刻 T7: 内核层加密传输
    App 写入 fd_app 的数据:
        → 经过 Ztunnel (fd1)
        → Kernel kTLS 加密
        → 网络发送: 1.2.3.4:12345 → 10.0.0.2:8080 (加密数据)
    
    四元组可见！Tcpdump 能看到: 1.2.3.4:12345 → 10.0.0.2:8080
```

### 5.2 Inbound 流程 (Ztunnel Y 接收)

```
时刻 T0: Ztunnel Y 接收连接
    Inbound listener (15008) accept() → fd_in
    对端地址: 1.2.3.4:12345 (保留！)
    本地地址: 10.0.0.2:8080

时刻 T1: TLS 握手 (用户态)
    获取本地证书: local_workload.fetch_certificate()
    创建 TLS 接受器: cert.inbound_acceptor()
    在 fd_in 上握手: tls_stream = acceptor.accept(fd_in)
    验证对方证书

时刻 T2: 提取 TLS 密钥
    从 tls_stream 提取密钥 (同 Outbound T5)

时刻 T3: 配置 kTLS
    配置 fd_in 为 kTLS socket

时刻 T4: RBAC 验证
    获取对端身份: peer_identity = extract_peer_identity(tls_stream)
    验证权限: rbac.assert_rbac(peer_identity, local_workload)

时刻 T5: 建立到 Pod2 的连接
    连接: pod_stream = TcpStream::connect(pod2_real_addr)
    这是 fd3

时刻 T6: 双向数据拷贝
    copy_bidirectional(fd_in, fd3)
    fd_in (kTLS) ↔ fd3 (plaintext)
    Kernel 自动解密 fd_in 的数据，传递给 fd3
```

### 5.3 完整时序图

```
Pod1          Ztunnel X        Network         Ztunnel Y        Pod2
 |                |               |                |              |
 |--connect()--->|               |                |              |
 |   (iptables)   |               |                |              |
 |                |               |                |              |
 |<--accept()-----|               |                |              |
 |     fd1        |               |                |              |
 |                |               |                |              |
 |<--TLS handshake (userspace)-->|                |              |
 |  ClientHello   |--encrypted-->|                |              |
 |  ServerHello   |<--encrypted--|                |              |
 |  Certificate   |--encrypted-->|                |              |
 |  Finished      |<--encrypted--|                |              |
 |                |               |                |              |
 |  [Extract Keys]                |                |              |
 |  [Config kTLS] |               |                |              |
 |                |               |                |              |
 |--app data----->|               |                |              |
 |                |=[Kernel encrypt]==>           |              |
 |                |  1.2.3.4:12345->10.0.0.2:8080 |              |
 |                |               |                |              |
 |                |               |----accept()-->|              |
 |                |               |      fd_in    |              |
 |                |               |                |              |
 |                |         [TLS handshake]       |              |
 |                |         [Extract Keys]        |              |
 |                |         [Config kTLS]         |              |
 |                |         [RBAC check]          |              |
 |                |               |                |              |
 |                |               |                |--connect()-->|
 |                |               |                |     fd3      |
 |                |               |                |              |
 |                |               |<=[Kernel decrypt]=            |
 |                |               |                |--fwd data-->|
 |                |               |                |              |
 |<---response-------------------------通过 kTLS 返回-------------|
```

## 6. 密钥配置接口

### 6.1 自动模式 (TLS 握手)

在正常运行时，密钥通过 TLS 握手自动协商，无需手动配置。

### 6.2 手动注入模式

支持外部系统配置密钥，用于特殊场景（测试、密钥预共享等）。

#### API 端点
```
POST /admin/ktls/keys
Content-Type: application/json

{
  "connection_id": {
    "src_addr": "1.2.3.4:12345",
    "dst_addr": "10.0.0.2:8080"
  },
  "tx_key": "a1b2c3d4...",
  "tx_iv": "e5f6g7h8...",
  "rx_key": "i9j0k1l2...",
  "rx_iv": "m3n4o5p6...",
  "cipher_suite": "TLS_AES_256_GCM_SHA384"
}
```

#### 文件配置
```bash
# 在 Ztunnel X 上配置发送端密钥
cat > /etc/ztunnel/ktls-keys-tx.json << EOF
[
  {
    "connection_id": {
      "src_addr": "1.2.3.4:12345",
      "dst_addr": "10.0.0.2:8080"
    },
    "tx_key": "...",
    "tx_iv": "...",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  }
]
EOF

# 在 Ztunnel Y 上配置接收端密钥
cat > /etc/ztunnel/ktls-keys-rx.json << EOF
[
  {
    "connection_id": {
      "src_addr": "1.2.3.4:12345",
      "dst_addr": "10.0.0.2:8080"
    },
    "rx_key": "...",
    "rx_iv": "...",
    "cipher_suite": "TLS_AES_256_GCM_SHA384"
  }
]
EOF
```

#### 使用示例
```rust
// 在 Ztunnel X
let key_manager = KeyManager::new();
key_manager.load_from_file("/etc/ztunnel/ktls-keys-tx.json").await?;

// 建立连接时
let conn_id = ConnectionId::new(src_addr, dst_addr);
if let Some(keys) = key_manager.get_keys(&conn_id).await {
    // 使用预配置的密钥
    ktls_conn.configure_ktls(keys).await?;
} else {
    // 执行正常的 TLS 握手
    // ...
}
```

## 7. 兼容性和回退

### 7.1 特性开关

```yaml
# config.yaml
ktls:
  enabled: false  # 默认禁用，保持 HBONE 行为
```

当 `enabled: false` 时，完全使用现有的 HBONE 流程。

### 7.2 按连接选择

可以根据目标工作负载选择使用 kTLS 还是 HBONE：

```rust
if ktls_config.enabled && workload.supports_ktls() {
    handle_outbound_ktls(...).await?;
} else {
    handle_outbound_hbone(...).await?;
}
```

## 8. 性能优化

### 8.1 减少数据拷贝

**HBONE 模式**：
```
App → Kernel → Userspace(Ztunnel) → Kernel → 
    Userspace(TLS) → Kernel → Network
```
至少 4 次拷贝

**kTLS 模式**：
```
App → Kernel(kTLS encrypt) → Network
```
仅 1 次拷贝

### 8.2 CPU 优化

- TLS 加解密在内核执行，利用硬件加速 (AES-NI)
- 减少上下文切换
- 无需 HTTP/2 协议开销

## 9. 安全考虑

### 9.1 密钥保护

- 密钥在内存中自动 zeroize
- 密钥传递使用安全通道
- 支持密钥轮换

### 9.2 身份验证

- 保持现有的 mTLS 证书验证
- RBAC 检查不变
- 支持相同的身份体系 (SPIFFE)

### 9.3 审计

- 保留所有访问日志
- 四元组清晰可见，便于审计
- 支持连接追踪

## 10. 局限性

1. **Linux 限制**: kTLS 仅在 Linux 4.13+ 可用
2. **TLS 1.3 限制**: 只支持 TLS 1.3，不支持 TLS 1.2
3. **Cipher 限制**: 只支持特定加密套件 (AES-GCM, ChaCha20-Poly1305)
4. **密钥提取**: 需要 rustls 暴露内部密钥
5. **HBONE 复用失效**: 无法复用连接，每个 socket 独立

## 11. 总结

kTLS 改造方案实现了：
- ✅ 真实四元组可见性
- ✅ 内核级 TLS 加密
- ✅ 更好的性能
- ✅ 灵活的密钥配置

同时保持了：
- ✅ mTLS 身份验证
- ✅ RBAC 授权
- ✅ 证书管理
- ✅ 向后兼容性
