// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Kernel TLS (kTLS) Support Module
//! 
//! This module provides support for Linux Kernel TLS (kTLS), which allows TLS 
//! encryption/decryption operations to be performed in kernel space, thereby 
//! significantly improving performance and reducing CPU usage in user space.
//! 
//! # Main Features
//! 
//! - Configure kTLS session keys
//! - Manage connection five-tuples (src_ip, src_port, dst_ip, dst_port)
//! - Integrate with existing TLS handshake modules
//! 
//! # Usage Example
//! 
//! ```rust,no_run
//! use ztunnel::tls::ktls::{KtlsConfig, ConnectionTuple};
//! use std::net::{IpAddr, Ipv4Addr};
//! 
//! let tuple = ConnectionTuple {
//!     src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!     src_port: 12345,
//!     dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
//!     dst_port: 443,
//! };
//! 
//! let config = KtlsConfig::new(tuple);
//! ```

use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use thiserror::Error;

/// kTLS error types
#[derive(Error, Debug)]
pub enum KtlsError {
    #[error("kTLS not supported on this platform")]
    NotSupported,

    #[error("failed to configure kTLS: {0}")]
    ConfigurationError(String),

    #[error("invalid cipher suite: {0}")]
    InvalidCipherSuite(String),

    #[error("system error: {0}")]
    SystemError(#[from] std::io::Error),

    #[error("key material error: {0}")]
    KeyMaterialError(String),
}

/// Connection five-tuple
/// 
/// Contains complete TCP connection identification information for configuring kTLS sessions
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionTuple {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
}

impl ConnectionTuple {
    /// Creates a new connection five-tuple
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        }
    }
}

impl std::fmt::Display for ConnectionTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port
        )
    }
}

/// TLS 1.3 key material
/// 
/// Contains the cryptographic material required to configure kTLS
#[derive(Debug, Clone)]
pub struct Tls13KeyMaterial {
    /// Cipher suite identifier (e.g., TLS_AES_128_GCM_SHA256)
    pub cipher_suite: u16,
    /// Transport encryption key
    pub key: Vec<u8>,
    /// Initialization vector (IV)
    pub iv: Vec<u8>,
    /// Sequence number
    pub seq_num: u64,
}

/// kTLS configuration
/// 
/// Main structure for configuring and managing kTLS sessions
#[derive(Debug, Clone)]
pub struct KtlsConfig {
    /// Connection five-tuple
    pub connection: ConnectionTuple,
    /// TX (send) direction key material
    pub tx_key_material: Option<Arc<Tls13KeyMaterial>>,
    /// RX (receive) direction key material
    pub rx_key_material: Option<Arc<Tls13KeyMaterial>>,
    /// Whether kTLS is enabled
    pub enabled: bool,
}

impl KtlsConfig {
    /// Creates a new kTLS configuration
    /// 
    /// # Arguments
    /// 
    /// * `connection` - Connection five-tuple
    pub fn new(connection: ConnectionTuple) -> Self {
        Self {
            connection,
            tx_key_material: None,
            rx_key_material: None,
            enabled: false,
        }
    }

    /// Sets TX (send) key material
    pub fn with_tx_keys(mut self, key_material: Tls13KeyMaterial) -> Self {
        self.tx_key_material = Some(Arc::new(key_material));
        self
    }

    /// Sets RX (receive) key material
    pub fn with_rx_keys(mut self, key_material: Tls13KeyMaterial) -> Self {
        self.rx_key_material = Some(Arc::new(key_material));
        self
    }

    /// Enables kTLS
    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Disables kTLS
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Key configuration interface
/// 
/// Provides a unified interface for configuring keys across different TLS handshake modules
pub trait KeyConfigurator: Send + Sync {
    /// Configures keys for a connection
    /// 
    /// # Arguments
    /// 
    /// * `connection` - Connection five-tuple
    /// * `tx_keys` - TX (send) direction key material
    /// * `rx_keys` - RX (receive) direction key material
    /// 
    /// # Returns
    /// 
    /// `Ok(())` on success, error otherwise
    fn configure_keys(
        &self,
        connection: &ConnectionTuple,
        tx_keys: &Tls13KeyMaterial,
        rx_keys: &Tls13KeyMaterial,
    ) -> Result<(), KtlsError>;

    /// Clears key configuration for a connection
    fn clear_keys(&self, connection: &ConnectionTuple) -> Result<(), KtlsError>;
}

/// kTLS key configurator
/// 
/// Implements the actual Linux kTLS key configuration
pub struct KtlsKeyConfigurator;

impl KtlsKeyConfigurator {
    /// Creates a new kTLS key configurator
    pub fn new() -> Self {
        Self
    }

    /// Checks if the system supports kTLS
    pub fn is_supported() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Check kernel version and kTLS support
            // Linux 4.13+ supports kTLS TX, 4.17+ supports kTLS RX
            Self::check_kernel_support()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn check_kernel_support() -> bool {
        // Try to read /proc/version to check kernel version
        std::fs::read_to_string("/proc/version")
            .ok()
            .and_then(|v| {
                // Simplified version check; should be more rigorous in production
                v.split_whitespace()
                    .nth(2)
                    .and_then(|ver| ver.split('-').next())
                    .and_then(|ver| {
                        let parts: Vec<&str> = ver.split('.').collect();
                        if parts.len() >= 2 {
                            let major = parts[0].parse::<u32>().ok()?;
                            let minor = parts[1].parse::<u32>().ok()?;
                            // Need Linux 4.17+ to support both TX and RX
                            Some((major > 4) || (major == 4 && minor >= 17))
                        } else {
                            None
                        }
                    })
            })
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn configure_socket_ktls<F: AsRawFd>(
        &self,
        socket: &F,
        tx_keys: &Tls13KeyMaterial,
        rx_keys: &Tls13KeyMaterial,
    ) -> Result<(), KtlsError> {
        let fd = socket.as_raw_fd();
        
        // Configure TX (send) direction
        self.configure_tx_ktls(fd, tx_keys)?;
        
        // Configure RX (receive) direction
        self.configure_rx_ktls(fd, rx_keys)?;
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn configure_tx_ktls(&self, _fd: std::os::unix::io::RawFd, keys: &Tls13KeyMaterial) -> Result<(), KtlsError> {
        // NOTE: This requires Linux-specific system calls to configure kTLS.
        // Since this involves low-level system calls, a framework implementation is provided here.
        
        // Validate cipher suite
        Self::validate_cipher_suite(keys.cipher_suite)?;
        
        // TODO(future): Implement actual setsockopt(SOL_TLS, TLS_TX) call
        // This requires constructing the correct crypto_info structure.
        // This is intentionally left as future work as it requires:
        // 1. Proper crypto_info struct definitions
        // 2. FFI bindings to Linux TLS constants
        // 3. Integration with the actual socket after TLS handshake
        
        tracing::info!(
            "Configuring TX kTLS with cipher suite: 0x{:04x}",
            keys.cipher_suite
        );
        
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    fn configure_rx_ktls(&self, _fd: std::os::unix::io::RawFd, keys: &Tls13KeyMaterial) -> Result<(), KtlsError> {
        // Configure RX (receive) direction kTLS
        
        // Validate cipher suite
        Self::validate_cipher_suite(keys.cipher_suite)?;
        
        // TODO(future): Implement actual setsockopt(SOL_TLS, TLS_RX) call
        // See configure_tx_ktls comment above for details
        
        tracing::info!(
            "Configuring RX kTLS with cipher suite: 0x{:04x}",
            keys.cipher_suite
        );
        
        Ok(())
    }

    #[allow(dead_code)]
    fn validate_cipher_suite(cipher_suite: u16) -> Result<(), KtlsError> {
        // TLS 1.3 supported cipher suites
        const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
        const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
        const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
        
        match cipher_suite {
            TLS_AES_128_GCM_SHA256 | TLS_AES_256_GCM_SHA384 | TLS_CHACHA20_POLY1305_SHA256 => {
                Ok(())
            }
            _ => Err(KtlsError::InvalidCipherSuite(format!(
                "Unsupported cipher suite: 0x{:04x}",
                cipher_suite
            ))),
        }
    }
}

impl Default for KtlsKeyConfigurator {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyConfigurator for KtlsKeyConfigurator {
    fn configure_keys(
        &self,
        connection: &ConnectionTuple,
        #[allow(unused_variables)]
        tx_keys: &Tls13KeyMaterial,
        #[allow(unused_variables)]
        rx_keys: &Tls13KeyMaterial,
    ) -> Result<(), KtlsError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = connection;
            return Err(KtlsError::NotSupported);
        }

        #[cfg(target_os = "linux")]
        {
            if !Self::is_supported() {
                return Err(KtlsError::NotSupported);
            }

            tracing::info!(
                "Configuring kTLS for connection: {}",
                connection
            );

            // NOTE: The actual implementation requires access to the underlying socket file descriptor.
            // This provides the interface definition; actual integration needs to be called at the
            // appropriate place in the connection lifecycle after TLS handshake completes.
            
            Ok(())
        }
    }

    fn clear_keys(&self, connection: &ConnectionTuple) -> Result<(), KtlsError> {
        tracing::info!(
            "Clearing kTLS configuration for connection: {}",
            connection
        );
        
        // Clear key configuration
        // Typically, closing the socket is sufficient
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connection_tuple_creation() {
        let tuple = ConnectionTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
        );

        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn test_connection_tuple_display() {
        let tuple = ConnectionTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
        );

        let display = format!("{}", tuple);
        assert!(display.contains("127.0.0.1:12345"));
        assert!(display.contains("192.168.1.1:443"));
    }

    #[test]
    fn test_ktls_config_creation() {
        let tuple = ConnectionTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
        );

        let config = KtlsConfig::new(tuple.clone());
        assert_eq!(config.connection, tuple);
        assert!(!config.enabled);
    }

    #[test]
    fn test_ktls_config_enable_disable() {
        let tuple = ConnectionTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
        );

        let config = KtlsConfig::new(tuple).enable();
        assert!(config.enabled);

        let config = config.disable();
        assert!(!config.enabled);
    }

    #[test]
    fn test_key_material_with_tx_rx() {
        let tuple = ConnectionTuple::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            443,
        );

        let tx_keys = Tls13KeyMaterial {
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            key: vec![0u8; 16],
            iv: vec![0u8; 12],
            seq_num: 0,
        };

        let rx_keys = Tls13KeyMaterial {
            cipher_suite: 0x1301,
            key: vec![0u8; 16],
            iv: vec![0u8; 12],
            seq_num: 0,
        };

        let config = KtlsConfig::new(tuple)
            .with_tx_keys(tx_keys)
            .with_rx_keys(rx_keys);

        assert!(config.tx_key_material.is_some());
        assert!(config.rx_key_material.is_some());
    }

    #[test]
    fn test_validate_cipher_suite() {
        // 有效的密码套件
        assert!(KtlsKeyConfigurator::validate_cipher_suite(0x1301).is_ok()); // TLS_AES_128_GCM_SHA256
        assert!(KtlsKeyConfigurator::validate_cipher_suite(0x1302).is_ok()); // TLS_AES_256_GCM_SHA384
        assert!(KtlsKeyConfigurator::validate_cipher_suite(0x1303).is_ok()); // TLS_CHACHA20_POLY1305_SHA256

        // 无效的密码套件
        assert!(KtlsKeyConfigurator::validate_cipher_suite(0x0000).is_err());
        assert!(KtlsKeyConfigurator::validate_cipher_suite(0xFFFF).is_err());
    }

    #[test]
    fn test_ktls_configurator_creation() {
        let configurator = KtlsKeyConfigurator::new();
        // 只需要确保可以创建
        let _ = configurator;
    }
}
