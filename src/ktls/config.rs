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

//! kTLS configuration module

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtlsConfig {
    /// Enable kTLS support
    pub enabled: bool,

    /// Path to the key configuration file for manual key injection
    /// This allows external systems to configure kTLS keys
    pub key_config_path: Option<PathBuf>,

    /// Socket buffer sizes for kTLS connections
    pub socket_buffer_size: Option<usize>,

    /// Enable direct socket mode (bypass HBONE)
    pub direct_socket_mode: bool,

    /// Preserve original source port (requires special kernel support)
    pub preserve_source_port: bool,

    /// Enable kTLS for inbound connections
    pub inbound_enabled: bool,

    /// Enable kTLS for outbound connections
    pub outbound_enabled: bool,

    /// Cipher suites to support (TLS 1.3 only)
    pub cipher_suites: Vec<CipherSuite>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256
    Aes128Gcm,
    /// TLS_AES_256_GCM_SHA384
    Aes256Gcm,
    /// TLS_CHACHA20_POLY1305_SHA256
    ChaCha20Poly1305,
}

impl Default for KtlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_config_path: None,
            socket_buffer_size: Some(4 * 1024 * 1024), // 4MB
            direct_socket_mode: true,
            preserve_source_port: false,
            inbound_enabled: true,
            outbound_enabled: true,
            cipher_suites: vec![
                CipherSuite::Aes256Gcm,
                CipherSuite::Aes128Gcm,
            ],
        }
    }
}

impl KtlsConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled {
            if self.cipher_suites.is_empty() {
                return Err("At least one cipher suite must be configured".to_string());
            }

            if !self.inbound_enabled && !self.outbound_enabled {
                return Err("At least one of inbound or outbound must be enabled".to_string());
            }

            #[cfg(not(target_os = "linux"))]
            {
                return Err("kTLS is only supported on Linux".to_string());
            }
        }

        Ok(())
    }

    /// Check if kTLS is enabled for the given direction
    pub fn is_enabled_for(&self, direction: Direction) -> bool {
        if !self.enabled {
            return false;
        }

        match direction {
            Direction::Inbound => self.inbound_enabled,
            Direction::Outbound => self.outbound_enabled,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl CipherSuite {
    /// Get the TLS 1.3 cipher suite code
    pub fn to_tls_code(&self) -> u16 {
        match self {
            CipherSuite::Aes128Gcm => 0x1301,        // TLS_AES_128_GCM_SHA256
            CipherSuite::Aes256Gcm => 0x1302,        // TLS_AES_256_GCM_SHA384
            CipherSuite::ChaCha20Poly1305 => 0x1303, // TLS_CHACHA20_POLY1305_SHA256
        }
    }

    /// Get the cipher name
    pub fn name(&self) -> &'static str {
        match self {
            CipherSuite::Aes128Gcm => "TLS_AES_128_GCM_SHA256",
            CipherSuite::Aes256Gcm => "TLS_AES_256_GCM_SHA384",
            CipherSuite::ChaCha20Poly1305 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }

    /// Parse from TLS code
    pub fn from_tls_code(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(CipherSuite::Aes128Gcm),
            0x1302 => Some(CipherSuite::Aes256Gcm),
            0x1303 => Some(CipherSuite::ChaCha20Poly1305),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KtlsConfig::default();
        assert!(!config.enabled);
        assert!(config.direct_socket_mode);
        assert!(!config.cipher_suites.is_empty());
    }

    #[test]
    fn test_config_validation() {
        let mut config = KtlsConfig::default();
        config.enabled = true;
        
        #[cfg(target_os = "linux")]
        {
            assert!(config.validate().is_ok());
        }

        config.cipher_suites.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_cipher_suite_codes() {
        assert_eq!(CipherSuite::Aes128Gcm.to_tls_code(), 0x1301);
        assert_eq!(CipherSuite::Aes256Gcm.to_tls_code(), 0x1302);
        assert_eq!(CipherSuite::ChaCha20Poly1305.to_tls_code(), 0x1303);
    }

    #[test]
    fn test_cipher_suite_parsing() {
        assert_eq!(
            CipherSuite::from_tls_code(0x1301),
            Some(CipherSuite::Aes128Gcm)
        );
        assert_eq!(
            CipherSuite::from_tls_code(0x1302),
            Some(CipherSuite::Aes256Gcm)
        );
        assert_eq!(CipherSuite::from_tls_code(0xFFFF), None);
    }
}
