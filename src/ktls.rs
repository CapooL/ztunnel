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

//! Kernel TLS (kTLS) support module
//!
//! This module provides support for Linux kernel TLS, which offloads TLS encryption/decryption
//! to the kernel. This allows for:
//! - Better performance through reduced userspace-kernel copies
//! - Preservation of original socket 4-tuple (src_ip:src_port -> dst_ip:dst_port)
//! - Network-visible encrypted traffic with the original connection parameters
//!
//! # Architecture
//!
//! kTLS flow:
//! 1. Perform TLS handshake in userspace (using rustls)
//! 2. Extract negotiated keys and crypto parameters
//! 3. Pass keys to kernel using setsockopt(SOL_TLS, TLS_TX/TLS_RX)
//! 4. Kernel handles encryption/decryption transparently
//!
//! # Security
//!
//! - Keys are securely transferred from userspace to kernel
//! - Only TLS 1.3 with specific cipher suites is supported
//! - Key material is zeroized after use

pub mod config;
pub mod connection;
pub mod key_manager;

#[cfg(target_os = "linux")]
pub mod linux;

pub use config::KtlsConfig;
pub use connection::{KtlsConnection, KtlsMode};
pub use key_manager::{KeyMaterial, KeyManager, TlsKeys};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum KtlsError {
    #[error("kTLS is not supported on this platform")]
    NotSupported,

    #[error("kTLS configuration error: {0}")]
    Config(String),

    #[error("Failed to configure kTLS socket: {0}")]
    SocketConfig(#[from] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    #[error("Key extraction failed: {0}")]
    KeyExtraction(String),

    #[error("Invalid cipher suite: {0}")]
    InvalidCipherSuite(String),

    #[error("Connection error: {0}")]
    Connection(String),
}

pub type Result<T> = std::result::Result<T, KtlsError>;

/// Check if kTLS is supported on this platform
pub fn is_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_ktls_supported()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Initialize kTLS subsystem
pub fn init() -> Result<()> {
    tracing::info!("Initializing kTLS subsystem");
    
    if !is_supported() {
        tracing::warn!("kTLS is not supported on this platform");
        return Err(KtlsError::NotSupported);
    }
    
    tracing::info!("kTLS support detected");
    Ok(())
}
