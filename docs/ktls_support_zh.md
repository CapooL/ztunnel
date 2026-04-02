# Kernel TLS (kTLS) 支持文档

## 概述

本文档介绍 ztunnel 中的 Kernel TLS (kTLS) 支持。kTLS 是 Linux 内核提供的一项功能，允许在内核空间执行 TLS 加密和解密操作，从而显著提高性能并降低用户空间的 CPU 使用率。

## 什么是 kTLS？

Kernel TLS (kTLS) 是从 Linux 内核 4.13 版本开始引入的功能，它将 TLS 协议的对称加密操作从用户空间转移到内核空间。主要优势包括：

- **性能提升**：减少数据在用户空间和内核空间之间的拷贝
- **CPU 利用率降低**：利用内核优化的加密实现
- **零拷贝支持**：可以与 sendfile、splice 等系统调用结合使用
- **硬件加速**：更容易利用硬件加密加速器

### 内核版本要求

- **Linux 4.13+**：支持 kTLS TX (发送方向)
- **Linux 4.17+**：支持 kTLS RX (接收方向)
- **Linux 5.2+**：完整的 TLS 1.3 支持

## 架构设计

### 模块结构

```
src/tls/
├── ktls.rs              # kTLS 核心实现
├── lib.rs               # TLS 库通用功能
├── workload.rs          # 工作负载证书管理
├── certificate.rs       # 证书处理
└── control.rs           # 控制平面认证
```

### 核心组件

#### 1. ConnectionTuple (连接五元组)

连接五元组唯一标识一个 TCP 连接，包含以下信息：

```rust
pub struct ConnectionTuple {
    pub src_ip: IpAddr,      // 源 IP 地址
    pub src_port: u16,       // 源端口
    pub dst_ip: IpAddr,      // 目标 IP 地址
    pub dst_port: u16,       // 目标端口
}
```

**使用示例：**

```rust
use ztunnel::tls::ktls::ConnectionTuple;
use std::net::{IpAddr, Ipv4Addr};

let tuple = ConnectionTuple::new(
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    12345,
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    443,
);

println!("连接: {}", tuple);
// 输出: 连接: 10.0.0.1:12345 -> 10.0.0.2:443
```

#### 2. Tls13KeyMaterial (密钥材料)

包含配置 kTLS 所需的加密材料：

```rust
pub struct Tls13KeyMaterial {
    pub cipher_suite: u16,   // 密码套件 (如 TLS_AES_128_GCM_SHA256)
    pub key: Vec<u8>,        // 对称加密密钥
    pub iv: Vec<u8>,         // 初始化向量
    pub seq_num: u64,        // 序列号
}
```

**支持的密码套件：**

| 密码套件 | 标识符 | 描述 |
|---------|--------|------|
| TLS_AES_128_GCM_SHA256 | 0x1301 | AES-128-GCM with SHA-256 |
| TLS_AES_256_GCM_SHA384 | 0x1302 | AES-256-GCM with SHA-384 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | ChaCha20-Poly1305 with SHA-256 |

#### 3. KtlsConfig (kTLS 配置)

管理 kTLS 会话的主要配置结构：

```rust
pub struct KtlsConfig {
    pub connection: ConnectionTuple,           // 连接信息
    pub tx_key_material: Option<...>,          // 发送密钥
    pub rx_key_material: Option<...>,          // 接收密钥
    pub enabled: bool,                         // 是否启用
}
```

**配置示例：**

```rust
use ztunnel::tls::ktls::{KtlsConfig, ConnectionTuple, Tls13KeyMaterial};

// 创建连接五元组
let connection = ConnectionTuple::new(...);

// 创建发送密钥材料
let tx_keys = Tls13KeyMaterial {
    cipher_suite: 0x1301,  // TLS_AES_128_GCM_SHA256
    key: vec![0u8; 16],
    iv: vec![0u8; 12],
    seq_num: 0,
};

// 创建接收密钥材料
let rx_keys = Tls13KeyMaterial {
    cipher_suite: 0x1301,
    key: vec![0u8; 16],
    iv: vec![0u8; 12],
    seq_num: 0,
};

// 配置 kTLS
let config = KtlsConfig::new(connection)
    .with_tx_keys(tx_keys)
    .with_rx_keys(rx_keys)
    .enable();
```

#### 4. KeyConfigurator (密钥配置接口)

提供统一的接口来配置不同类型的 TLS 握手模块：

```rust
pub trait KeyConfigurator: Send + Sync {
    fn configure_keys(
        &self,
        connection: &ConnectionTuple,
        tx_keys: &Tls13KeyMaterial,
        rx_keys: &Tls13KeyMaterial,
    ) -> Result<(), KtlsError>;

    fn clear_keys(&self, connection: &ConnectionTuple) -> Result<(), KtlsError>;
}
```

这个 trait 的设计考虑了未来可能接入其他握手模块的需求，提供了清晰的密钥配置接口。

## 使用指南

### 基本使用流程

1. **检查系统支持**

```rust
use ztunnel::tls::ktls::KtlsKeyConfigurator;

if KtlsKeyConfigurator::is_supported() {
    println!("系统支持 kTLS");
} else {
    println!("系统不支持 kTLS，将使用传统 TLS");
}
```

2. **创建密钥配置器**

```rust
use ztunnel::tls::ktls::KtlsKeyConfigurator;

let configurator = KtlsKeyConfigurator::new();
```

3. **配置连接密钥**

```rust
use ztunnel::tls::ktls::{ConnectionTuple, Tls13KeyMaterial};

let connection = ConnectionTuple::new(/* ... */);
let tx_keys = Tls13KeyMaterial { /* ... */ };
let rx_keys = Tls13KeyMaterial { /* ... */ };

configurator.configure_keys(&connection, &tx_keys, &rx_keys)?;
```

4. **清理配置**

```rust
configurator.clear_keys(&connection)?;
```

### 与现有 TLS 握手集成

kTLS 模块设计为与现有的 rustls 握手流程无缝集成：

1. **握手阶段**：使用现有的 rustls 完成 TLS 握手
2. **密钥提取**：握手完成后提取对称密钥材料
3. **kTLS 激活**：使用提取的密钥配置 kTLS
4. **数据传输**：后续数据传输自动使用 kTLS 加速

## 配置参数详解

### 连接五元组参数

| 参数 | 类型 | 说明 | 示例 |
|-----|------|------|------|
| src_ip | IpAddr | 源 IP 地址 | 10.0.0.1 |
| src_port | u16 | 源端口号 | 12345 |
| dst_ip | IpAddr | 目标 IP 地址 | 192.168.1.1 |
| dst_port | u16 | 目标端口号 | 443 |

### 密钥材料参数

| 参数 | 类型 | 说明 | 大小 |
|-----|------|------|------|
| cipher_suite | u16 | 密码套件标识符 | 2 字节 |
| key | Vec\<u8\> | 对称加密密钥 | 16/32 字节 |
| iv | Vec\<u8\> | 初始化向量 | 12 字节 |
| seq_num | u64 | 序列号 | 8 字节 |

**注意事项：**

- 密钥长度取决于密码套件（AES-128 为 16 字节，AES-256 为 32 字节）
- IV 长度固定为 12 字节（GCM 模式）
- 序列号必须与 TLS 记录层同步

## 错误处理

### 错误类型

```rust
pub enum KtlsError {
    NotSupported,                    // 系统不支持 kTLS
    ConfigurationError(String),      // 配置错误
    InvalidCipherSuite(String),      // 无效的密码套件
    SystemError(std::io::Error),     // 系统错误
    KeyMaterialError(String),        // 密钥材料错误
}
```

## 性能优化建议

### 1. 选择合适的密码套件

- **AES-GCM**：在支持 AES-NI 的 CPU 上性能最佳
- **ChaCha20-Poly1305**：在不支持 AES-NI 的 ARM 设备上表现更好

### 2. 批量操作

kTLS 在处理大数据块时性能优势更明显。

## 安全考虑

### 1. 密钥管理

- 密钥材料必须通过安全的 TLS 握手获得
- 不要在代码中硬编码密钥
- 使用后及时清除内存中的密钥数据

### 2. 版本检查

在生产环境中部署前，务必检查内核版本：

```bash
uname -r
# 输出应该 >= 4.17.0
```

## 未来扩展

### 计划的功能

1. **动态密钥更新**：支持 TLS 会话密钥轮换
2. **更多密码套件**：支持更多 TLS 1.3 密码套件
3. **性能监控**：内置性能指标收集
4. **其他握手模块**：支持除 rustls 外的其他 TLS 库

### 扩展接口

`KeyConfigurator` trait 的设计使得未来可以轻松添加新的握手模块：

```rust
// 未来可能的其他实现
impl KeyConfigurator for OpenSslKeyConfigurator { /* ... */ }
impl KeyConfigurator for BoringSSLKeyConfigurator { /* ... */ }
```

## 参考资料

- [Kernel TLS Documentation](https://www.kernel.org/doc/html/latest/networking/tls.html)
- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)

## 许可证

Copyright Istio Authors - Licensed under the Apache License, Version 2.0
