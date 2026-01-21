# rustls 密钥提取支持确认

**日期**: 2026-01-21  
**重要发现**: rustls **完全支持**密钥提取！

## 研究结果

经过对 rustls 源码的详细调查（GitHub: https://github.com/rustls/rustls），确认以下事实：

### 1. dangerous_extract_secrets() API

rustls 提供了专门用于 kTLS 配置的 API：

**位置**: `rustls/src/conn/mod.rs`

```rust
/// Extract secrets, so they can be used when configuring kTLS, for example.
/// Should be used with care as it exposes secret key material.
pub fn dangerous_extract_secrets(self) -> Result<ExtractedSecrets, Error> {
    self.core.dangerous_extract_secrets()
}
```

**注意**: 官方注释明确说明此 API 是为 kTLS 设计的！

### 2. ExtractedSecrets 结构

**位置**: `rustls/src/suites.rs`

```rust
pub struct ExtractedSecrets {
    /// sequence number and secrets for the "tx" (transmit) direction
    pub tx: (u64, ConnectionTrafficSecrets),

    /// sequence number and secrets for the "rx" (receive) direction
    pub rx: (u64, ConnectionTrafficSecrets),
}
```

完美匹配 kTLS 需求：
- TX 方向：序列号 + 密钥材料
- RX 方向：序列号 + 密钥材料

### 3. ConnectionTrafficSecrets 枚举

**位置**: `rustls/src/suites.rs`

```rust
/// Secrets used to encrypt/decrypt data in a TLS session.
///
/// These can be used to configure kTLS for a socket in one direction.
/// The only other piece of information needed is the sequence number,
/// which is provided alongside in [ExtractedSecrets].
pub enum ConnectionTrafficSecrets {
    /// Secrets for the AES_128_GCM AEAD algorithm
    Aes128Gcm {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },

    /// Secrets for the AES_256_GCM AEAD algorithm
    Aes256Gcm {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },

    /// Secrets for the CHACHA20_POLY1305 AEAD algorithm
    Chacha20Poly1305 {
        /// AEAD Key
        key: AeadKey,
        /// Initialization vector
        iv: Iv,
    },
}
```

支持的加密套件：
- AES-128-GCM ✅
- AES-256-GCM ✅
- ChaCha20-Poly1305 ✅

与 Linux kTLS 支持的套件完全匹配！

### 4. KeyLog trait（备选方案）

**位置**: `rustls/src/key_log.rs`

```rust
/// This trait represents the ability to do something useful
/// with key material, such as logging it to a file for debugging.
pub trait KeyLog: Debug + Send + Sync {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]);
}
```

支持记录以下密钥：
- `CLIENT_TRAFFIC_SECRET_0`
- `SERVER_TRAFFIC_SECRET_0`
- `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
- `SERVER_HANDSHAKE_TRAFFIC_SECRET`
- `EXPORTER_SECRET`

## 使用示例

### 从 TLS 连接提取密钥

```rust
use rustls::Connection;
use tokio_rustls::TlsStream;

// 在 TLS 握手完成后
let tls_stream: TlsStream<TcpStream> = /* ... */;
let (io, connection) = tls_stream.into_inner();

// 提取密钥（消费 connection）
let secrets = connection.dangerous_extract_secrets()?;

// 使用密钥配置 kTLS
let tx_secrets = secrets.tx.1;  // ConnectionTrafficSecrets
let tx_seq = secrets.tx.0;      // u64 sequence number
let rx_secrets = secrets.rx.1;
let rx_seq = secrets.rx.0;

match tx_secrets {
    ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
        // 配置 kTLS TX
        let key_material = KeyMaterial {
            tls_version: 0x0304,  // TLS 1.3
            cipher_suite: 0x1302, // TLS_AES_256_GCM_SHA384
            key: key.as_ref().to_vec(),
            iv: iv.as_ref().to_vec(),
            seq: tx_seq,
        };
        configure_ktls_tx(&io, &key_material)?;
    }
    // ... 其他加密套件
}
```

## 对项目的影响

### 之前的评估（错误）❌

- ✗ rustls 不暴露密钥
- ✗ 需要切换到 OpenSSL backend
- ✗ 或需要 fork rustls
- ✗ 只能使用预共享密钥方案

### 新的评估（正确）✅

- ✓ rustls **完全支持**密钥提取
- ✓ 使用 `dangerous_extract_secrets()` API
- ✓ 专门为 kTLS 设计
- ✓ 可以实现**完全自动化**的 kTLS

### 实施时间更新

原估算：
- 切换 TLS backend：1-2周
- 实现密钥提取：1周
- **总计：2-3周额外工作**

新估算：
- ✅ 无需切换 TLS backend
- ✅ 密钥提取 API 已存在
- **额外工作：0周！**

## 下一步行动

### 立即可行（1-2周）

1. **更新 key_extraction.rs**
   - 实现基于 `dangerous_extract_secrets()` 的提取
   - 移除预共享密钥依赖

2. **实施 outbound/inbound 集成**
   - 使用 rustls 的 TLS 连接
   - 握手完成后提取密钥
   - 配置 kTLS
   - 继续使用 socket

3. **测试验证**
   - 验证四元组可见性
   - 验证数据加密
   - 性能测试

### 无需做的事情

- ❌ 切换到 OpenSSL backend
- ❌ Fork rustls
- ❌ 维护预共享密钥系统
- ❌ 手动配置密钥

## 技术细节

### rustls Connection 生命周期

```rust
// 1. 建立 TLS 连接
let connector = TlsConnector::from(Arc::new(client_config));
let tls_stream = connector.connect(domain, tcp_stream).await?;

// 2. 使用连接进行数据传输（可选）
// 或直接提取密钥

// 3. 提取密钥（消费连接）
let (tcp_stream, connection) = tls_stream.into_inner();
let secrets = connection.dangerous_extract_secrets()?;

// 4. 配置 kTLS
configure_ktls(&tcp_stream, &secrets)?;

// 5. 继续使用 tcp_stream（现在有 kTLS 加密）
```

### 与 kTLS 的完美匹配

| rustls 提供 | kTLS 需要 | 匹配度 |
|------------|----------|-------|
| key (AeadKey) | 加密密钥 | ✅ 完美 |
| iv (Iv) | 初始化向量 | ✅ 完美 |
| sequence number | 序列号 | ✅ 完美 |
| cipher suite | 算法标识 | ✅ 完美 |

## 结论

**rustls 完全支持 kTLS 密钥提取！**

这意味着：
1. ✅ 可以实现完全自动化的 kTLS
2. ✅ 无需额外的 backend 切换
3. ✅ 无需预共享密钥
4. ✅ 开发时间大幅缩短

**项目可以立即按原计划推进！**

---

**参考资料**:
- rustls GitHub: https://github.com/rustls/rustls
- API 文档: `rustls/src/conn/mod.rs::dangerous_extract_secrets()`
- 密钥结构: `rustls/src/suites.rs::ExtractedSecrets`
- KeyLog trait: `rustls/src/key_log.rs::KeyLog`
