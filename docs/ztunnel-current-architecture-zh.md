# Ztunnel 现有架构分析文档

## 1. 整体架构概述

Ztunnel 是 Istio Ambient Mesh 的核心组件，作为节点代理运行在每个 Kubernetes 节点上。它通过 HBONE (HTTP/2-Based One Network Edge) 协议实现 Pod 间的安全通信。

## 2. 数据流程详解

### 2.1 完整通信链路

当 Node X 上的 Pod1 发送数据到 Node Y 上的 Pod2 时，数据流经以下路径：

```
Pod1 (1.2.3.4:12345) 
    ↓ [fd1] TCP明文连接
Ztunnel X (Outbound Listener:15001)
    ↓ [fd2] mTLS+HBONE连接
Ztunnel Y (Inbound Listener:15008)
    ↓ [fd3] TCP明文连接
Pod2 (10.0.0.2:8080)
```

### 2.2 三个Socket连接详解

#### fd1: Pod1 → Ztunnel X (Outbound)
- **类型**: TCP明文连接
- **源地址**: Pod1的IP:临时端口 (例如: 1.2.3.4:12345)
- **目标地址**: Ztunnel的outbound监听器 (127.0.0.1:15001)
- **建立方式**: 
  - Pod1的流量被iptables规则劫持
  - 重定向到Ztunnel的15001端口
  - Ztunnel的Outbound模块接受连接
- **代码位置**: `src/proxy/outbound.rs`

```rust
// outbound.rs: 88-93行
let socket = self.listener.accept().await;
match socket {
    Ok((stream, _remote)) => {
        // 接收来自Pod的连接
    }
}
```

#### fd2: Ztunnel X → Ztunnel Y (HBONE)
- **类型**: mTLS加密的TCP连接 + HTTP/2 CONNECT隧道
- **源地址**: **Pod1的IP** (通过freebind欺骗) : **系统分配的临时端口**
- **目标地址**: Ztunnel Y的IP:15008
- **协议栈**: TCP → mTLS → HTTP/2 → CONNECT隧道 → 数据流

##### 源端口问题回答
问题中提到："src_port：不确定，请告诉我是fd1里的src_port，还是fd2新产生的?"

**答案**: fd2的src_port是**新产生的临时端口**，而不是fd1的src_port。原因如下：

1. **fd1的源端口**: Pod1内部应用程序创建socket时的临时端口 (例如:12345)
2. **fd2的源端口**: Ztunnel X创建新的socket连接时，操作系统分配的临时端口 (例如:45678)
3. **源IP保持**: 虽然fd2的源端口是新的，但源IP通过freebind技术欺骗为Pod1的IP
4. **原始端口传递**: Pod1的原始端口信息通过HBONE协议的HTTP头部(`FORWARDED`)传递给Ztunnel Y

##### fd2的四元组
```
源IP:   pod1_ip (1.2.3.4) - 通过freebind欺骗保留
源Port: 系统新分配 (例如: 45678) - 非fd1的12345
目标IP: ztunnel_y_ip (10.0.0.5) 
目标Port: 15008 - 固定的HBONE端口
```

##### 建立流程 (代码流程)

**第一步: 获取证书和创建连接器** (`src/proxy/pool.rs`)
```rust
// pool.rs: 85-95行
let cert = self.local_workload.fetch_certificate(&key.src_id).await?;
let connector = cert.outbound_connector(key.dst_id.clone())?;
```

**第二步: TCP连接建立** (`src/proxy/outbound.rs`)
```rust
// 使用freebind技术欺骗源IP为Pod1的IP
let tcp_stream = super::freebind_connect(
    None,           // 源端口由系统分配
    key.dst,        // 目标: Ztunnel Y:15008
    self.socket_factory.as_ref()
).await?;
```

**第三步: mTLS握手**
```rust
// pool.rs: 90行
let tls_stream = connector.connect(tcp_stream).await?;
// 双向证书验证，建立加密通道
```

**第四步: HTTP/2握手**
```rust
// pool.rs: 91行
let sender = h2::client::spawn_connection(
    cfg,
    tls_stream,
    driver_drain,
    wl_key
).await?;
```

**第五步: HBONE CONNECT请求** (`src/proxy/outbound.rs`)
```rust
// outbound.rs: 构建HTTP/2 CONNECT请求
let mut builder = Request::builder()
    .uri(format!("http://{}", hbone_addr)) // HBONE目标地址
    .method(Method::CONNECT);

// 添加元数据头部
builder = builder
    .header(FORWARDED, format!("for={}:{};proto=tcp", orig_src, orig_port))
    .header(BAGGAGE, baggage_header)
    .header(TRACEPARENT, trace_parent);

let req = builder.body(())?;
let response_stream = sender.send_request(req).await?;
```

**第六步: 连接升级为字节流**
- HTTP/2响应状态码200表示CONNECT成功
- 之后该HTTP/2流变成双向字节管道
- 应用数据在此管道中传输

#### fd3: Ztunnel Y → Pod2 (Inbound)
- **类型**: TCP明文连接 (可选保留源IP)
- **源地址**: 
  - 保留源IP模式: Pod1的IP:临时端口 (1.2.3.4:新端口)
  - 普通模式: Ztunnel Y的IP:临时端口
- **目标地址**: Pod2的真实IP:端口 (10.0.0.2:8080)
- **建立方式**:
  - Ztunnel Y解析HBONE请求中的目标地址
  - 验证RBAC权限
  - 建立到目标Pod的连接
  - 进行双向数据拷贝
- **代码位置**: `src/proxy/inbound.rs`

```rust
// inbound.rs: serve_h2_request函数
async fn serve_h2_request(
    request_parts: RequestParts,
    orig_src: SocketAddr,
    orig_dst: SocketAddr,
    pi: Arc<ProxyInputs>,
) -> Result<(), Error> {
    // 1. 解析HBONE目标地址
    let hbone_addr = request_parts.uri.authority().unwrap();
    
    // 2. 验证RBAC
    let rbac_ctx = build_rbac_context(...);
    pi.rbac.assert_rbac(&rbac_ctx).await?;
    
    // 3. 建立到Pod2的连接
    let mut outbound = TcpStream::connect(real_dst).await?;
    
    // 4. 返回200 OK响应
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap();
    request_parts.send_response.send_response(response, false)?;
    
    // 5. 双向数据拷贝
    copy::copy_bidirectional(&mut inbound_stream, &mut outbound).await?;
}
```

## 3. HBONE协议核心机制

### 3.1 什么是HBONE

**HBONE** = HTTP/2-Based One Network Edge Protocol

核心思想：利用HTTP/2的CONNECT方法创建虚拟隧道，在mTLS加密连接上传输原始TCP流量。

### 3.2 为什么使用HBONE

1. **安全性**: 利用mTLS提供双向认证和加密
2. **元数据传递**: HTTP/2头部可携带丰富的连接元数据
3. **多路复用**: 单个TCP连接可承载多个HTTP/2流，减少连接开销
4. **穿透性**: HTTP/2协议更容易穿透企业防火墙
5. **可扩展性**: 易于添加新的头部和功能

### 3.3 HBONE请求格式

```http
CONNECT <target_ip>:<target_port> HTTP/2
Host: <target_ip>:<target_port>
Forwarded: for=<original_src_ip>:<original_src_port>;proto=tcp
Baggage: k8s.cluster.name=<cluster>,k8s.namespace.name=<namespace>,...
Traceparent: 00-<trace_id>-<span_id>-<flags>
```

### 3.4 元数据传递

- **FORWARDED头部**: 保留原始客户端的IP和端口
- **BAGGAGE头部**: 传递源Pod的集群、命名空间、工作负载信息
- **TRACEPARENT头部**: 分布式追踪的上下文信息

这些元数据在fd2上通过HTTP头部传递，确保Ztunnel Y知道：
- 流量的真实来源
- 应该建立fd3到哪个目标
- 如何进行RBAC验证

## 4. 连接池和复用

### 4.1 WorkloadHBONEPool

位置: `src/proxy/pool.rs`

Ztunnel维护了一个连接池来复用HBONE连接（fd2）。连接池的键值为：

```rust
pub struct WorkloadKey {
    pub src_id: Identity,      // 源工作负载身份
    pub dst_id: Vec<Identity>, // 目标工作负载身份列表
    pub dst: SocketAddr,       // 目标地址
    pub src: IpAddr,           // 源IP（用于freebind）
}
```

### 4.2 多路复用策略

- **单个HTTP/2连接**可支持多个并发流 (max_concurrent_streams配置)
- **多个Pod连接**可共享同一个HBONE连接
- **流量隔离**通过HTTP/2流ID区分
- **自动回收**当流数量达到上限或连接空闲超时

示例：
```
Pod1 -> Ztunnel X ─┐
                   ├─→ [同一个fd2: HTTP/2连接] ─→ Ztunnel Y
Pod3 -> Ztunnel X ─┘    (多个HTTP/2流复用)
```

## 5. 证书和身份验证

### 5.1 证书获取

```rust
// src/identity/identity.rs
impl LocalWorkloadInformation {
    pub async fn fetch_certificate(&self, id: &Identity) 
        -> Result<SecretManager, Error> {
        // 从CA获取证书
        // 或从本地缓存读取
    }
}
```

### 5.2 mTLS验证流程

**Client Side (Ztunnel X)**:
1. 使用本地工作负载证书 (client cert)
2. 验证服务端证书的SAN匹配目标身份

**Server Side (Ztunnel Y)**:
1. 提供服务端证书
2. 验证客户端证书
3. 检查客户端身份是否有权访问目标工作负载

## 6. 端口说明

| 端口 | 用途 | 绑定位置 |
|-----|------|---------|
| 15001 | Outbound流量捕获 | Pod网络命名空间 |
| 15006 | Inbound明文流量捕获 | Pod网络命名空间 |
| 15008 | Inbound HBONE流量捕获 | Pod网络命名空间 |
| 15080 | Outbound Socks5代理 | Pod网络命名空间 |
| 15053 | DNS流量捕获 | Pod网络命名空间 |
| 15021 | 就绪检查 | 宿主机网络 |
| 15000 | 管理接口 | 宿主机网络(localhost) |
| 15020 | 监控指标 | 宿主机网络 |

## 7. 数据包在fd2上的实际格式

### 7.1 网络层视角

从网络监控工具(如tcpdump)看到的fd2数据包:

```
IP Header:
  Source IP: 1.2.3.4 (Pod1的IP)
  Source Port: 45678 (系统新分配)
  Dest IP: 10.0.0.5 (Ztunnel Y的IP)
  Dest Port: 15008 (HBONE端口)

TCP Header:
  [TCP三次握手，序列号等]

TLS Record:
  [加密的内容，包括:]
    - TLS Handshake记录
    - HTTP/2 CONNECT请求
    - HTTP/2 DATA帧(实际应用数据)
```

### 7.2 解密后的内容

如果能解密TLS，会看到:

```
HTTP/2 帧序列:
1. SETTINGS帧: 配置HTTP/2参数
2. HEADERS帧: CONNECT请求头
   - :method: CONNECT
   - :authority: 10.0.0.2:8080
   - forwarded: for=1.2.3.4:12345;proto=tcp
3. DATA帧: 应用层数据(来自Pod1的原始TCP流)
4. DATA帧: 应用层数据(来自Pod2的响应)
```

## 8. 问题总结

### 8.1 当前架构的问题

1. **四元组不可见**: 
   - 实际网络中只能看到 `1.2.3.4:45678 -> 10.0.0.5:15008`
   - 无法审计到逻辑上的 `1.2.3.4:12345 -> 10.0.0.2:8080`

2. **协议封装复杂**:
   - TCP → TLS → HTTP/2 → CONNECT → 应用数据
   - 多层封装增加了延迟和CPU开销

3. **调试困难**:
   - 抓包只能看到加密的TLS流量
   - 需要特殊工具解密HTTP/2才能看到CONNECT请求

### 8.2 解决方案目标

使用kTLS技术，创建直连socket (fd4)：
- 四元组: `1.2.3.4:12345 -> 10.0.0.2:8080` (真实的Pod对Pod)
- 加密: 通过内核kTLS实现，无需HTTP/2封装
- 性能: 减少用户态-内核态数据拷贝
- 可审计: 网络层四元组清晰可见

## 9. 相关代码文件

| 文件路径 | 功能 |
|---------|------|
| `src/proxy/outbound.rs` | Outbound监听器和连接处理 |
| `src/proxy/inbound.rs` | Inbound监听器和HBONE服务 |
| `src/proxy/pool.rs` | HBONE连接池管理 |
| `src/proxy/h2/client.rs` | HTTP/2客户端(HBONE) |
| `src/proxy/h2/server.rs` | HTTP/2服务端(HBONE) |
| `src/socket.rs` | Socket工厂和freebind实现 |
| `src/copy.rs` | 双向数据拷贝 |
| `src/tls.rs` | TLS配置和证书管理 |
| `src/identity/` | 身份和证书管理 |

## 10. 总结

Ztunnel通过HBONE协议实现了：
- ✅ 安全的跨节点通信 (mTLS)
- ✅ 身份验证和RBAC
- ✅ 连接复用和性能优化
- ✅ 丰富的元数据传递
- ❌ 但牺牲了真实四元组的可见性

下一步将实现kTLS方案，在保持安全性的同时恢复四元组的网络可见性。
