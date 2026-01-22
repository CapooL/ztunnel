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

//! Key extraction utilities for kTLS
//!
//! This module provides functionality to extract TLS keys from established connections.
//! It supports multiple strategies:
//!
//! 1. Rustls automatic extraction via `dangerous_extract_secrets()` (primary method)
//! 2. Pre-shared keys from KeyManager (for testing and manual configuration)
//! 3. SSLKEYLOGFILE-based extraction (for debugging)

use crate::ktls::{KeyMaterial, KtlsError, Result, TlsKeys};
use crate::ktls::key_manager::{ConnectionId, KeyManager};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use rustls::{ExtractedSecrets, ConnectionTrafficSecrets};

/// Key extraction strategy
#[derive(Clone)]
pub enum KeyExtractionStrategy {
    /// Use rustls dangerous_extract_secrets() - primary method
    RustlsExtract,
    
    /// Use pre-configured keys from KeyManager
    PreShared(Arc<KeyManager>),
    
    /// Use SSLKEYLOGFILE for debugging
    #[cfg(debug_assertions)]
    SslKeyLog,
    
    /// Mock keys for testing
    #[cfg(test)]
    Mock,
}

/// Key extractor
pub struct KeyExtractor {
    strategy: KeyExtractionStrategy,
}

impl KeyExtractor {
    /// Create a new key extractor with the given strategy
    pub fn new(strategy: KeyExtractionStrategy) -> Self {
        Self { strategy }
    }

    /// Create a key extractor using pre-shared keys
    pub fn with_preshared_keys(key_manager: Arc<KeyManager>) -> Self {
        Self {
            strategy: KeyExtractionStrategy::PreShared(key_manager),
        }
    }

    /// Extract keys for a connection
    ///
    /// This function attempts to extract TLS keys using the configured strategy.
    /// For pre-shared keys, it looks up the keys in the KeyManager.
    ///
    /// # Arguments
    ///
    /// * `local_addr` - Local socket address
    /// * `remote_addr` - Remote socket address
    /// * `is_client` - Whether this is the client side of the connection
    ///
    /// # Returns
    ///
    /// Returns `TlsKeys` if extraction succeeds, or an error otherwise.
    pub async fn extract_keys(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        is_client: bool,
    ) -> Result<TlsKeys> {
        match &self.strategy {
            KeyExtractionStrategy::RustlsExtract => {
                // This will be used after TLS handshake completes
                // The actual extraction happens in convert_rustls_secrets()
                info!(
                    "Using rustls key extraction for {}:{} -> {}:{}",
                    local_addr.ip(), local_addr.port(),
                    remote_addr.ip(), remote_addr.port()
                );
                Err(KtlsError::KeyExtraction(
                    "Rustls extraction requires calling extract_from_rustls_connection()".to_string(),
                ))
            }
            
            KeyExtractionStrategy::PreShared(manager) => {
                // For client: local is source, remote is destination
                // For server: remote is source, local is destination
                let conn_id = if is_client {
                    ConnectionId::new(local_addr, remote_addr)
                } else {
                    ConnectionId::new(remote_addr, local_addr)
                };

                debug!(
                    "Extracting pre-shared keys for connection: {} (is_client: {})",
                    conn_id, is_client
                );

                manager
                    .get_keys(&conn_id)
                    .await
                    .ok_or_else(|| {
                        KtlsError::KeyExtraction(format!(
                            "No pre-shared keys found for connection: {}",
                            conn_id
                        ))
                    })
            }

            #[cfg(debug_assertions)]
            KeyExtractionStrategy::SslKeyLog => {
                warn!("SSLKEYLOGFILE extraction not yet implemented");
                Err(KtlsError::KeyExtraction(
                    "SSLKEYLOGFILE extraction not implemented".to_string(),
                ))
            }

            #[cfg(test)]
            KeyExtractionStrategy::Mock => {
                // Generate mock keys for testing
                Ok(create_mock_keys())
            }
        }
    }

    /// Extract keys with connection ID
    pub async fn extract_keys_by_id(&self, conn_id: &ConnectionId) -> Result<TlsKeys> {
        match &self.strategy {
            KeyExtractionStrategy::RustlsExtract => {
                Err(KtlsError::KeyExtraction(
                    "Rustls extraction requires calling extract_from_rustls_connection()".to_string(),
                ))
            }
            
            KeyExtractionStrategy::PreShared(manager) => {
                debug!("Extracting pre-shared keys for connection: {}", conn_id);
                manager
                    .get_keys(conn_id)
                    .await
                    .ok_or_else(|| {
                        KtlsError::KeyExtraction(format!(
                            "No pre-shared keys found for connection: {}",
                            conn_id
                        ))
                    })
            }

            #[cfg(debug_assertions)]
            KeyExtractionStrategy::SslKeyLog => {
                Err(KtlsError::KeyExtraction(
                    "SSLKEYLOGFILE extraction not implemented".to_string(),
                ))
            }

            #[cfg(test)]
            KeyExtractionStrategy::Mock => Ok(create_mock_keys()),
        }
    }
}

/// Create mock keys for testing
#[cfg(test)]
fn create_mock_keys() -> TlsKeys {
    TlsKeys {
        tx: KeyMaterial::new(
            0x0304, // TLS 1.3
            0x1302, // TLS_AES_256_GCM_SHA384
            vec![0u8; 32],
            vec![0u8; 12],
        ),
        rx: KeyMaterial::new(
            0x0304,
            0x1302,
            vec![1u8; 32],
            vec![1u8; 12],
        ),
    }
}

/// Helper to extract keys from a TCP connection
///
/// This is a convenience function for the most common use case.
pub async fn extract_keys_from_connection(
    key_manager: Arc<KeyManager>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    is_client: bool,
) -> Result<TlsKeys> {
    let extractor = KeyExtractor::with_preshared_keys(key_manager);
    extractor.extract_keys(local_addr, remote_addr, is_client).await
}

/// Convert rustls extracted secrets to kTLS key material
///
/// This function takes the secrets extracted from rustls via `dangerous_extract_secrets()`
/// and converts them to the format required by Linux kTLS.
///
/// # Example
///
/// ```ignore
/// use rustls::Connection;
///
/// let tls_stream = connector.connect(domain, tcp_stream).await?;
/// let (tcp_stream, connection) = tls_stream.into_inner();
/// let secrets = connection.dangerous_extract_secrets()?;
///
/// let keys = convert_rustls_secrets(&secrets)?;
/// ```
pub fn convert_rustls_secrets(secrets: ExtractedSecrets) -> Result<TlsKeys> {
    let (tx_seq, tx_secrets) = secrets.tx;
    let (rx_seq, rx_secrets) = secrets.rx;

    // Convert TX secrets
    let tx_material = match tx_secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304, // TLS 1.3
                cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: tx_seq,
            }
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304, // TLS 1.3
                cipher_suite: 0x1302, // TLS_AES_256_GCM_SHA384
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: tx_seq,
            }
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304, // TLS 1.3
                cipher_suite: 0x1303, // TLS_CHACHA20_POLY1305_SHA256
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: tx_seq,
            }
        }
        _ => {
            return Err(KtlsError::InvalidCipherSuite(
                "Unsupported cipher suite for kTLS".to_string()
            ));
        }
    };

    // Convert RX secrets
    let rx_material = match rx_secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304,
                cipher_suite: 0x1301,
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: rx_seq,
            }
        }
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304,
                cipher_suite: 0x1302,
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: rx_seq,
            }
        }
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            KeyMaterial {
                tls_version: 0x0304,
                cipher_suite: 0x1303,
                key: key.as_ref().to_vec(),
                iv: iv.as_ref().to_vec(),
                seq: rx_seq,
            }
        }
        _ => {
            return Err(KtlsError::InvalidCipherSuite(
                "Unsupported cipher suite for kTLS".to_string()
            ));
        }
    };

    Ok(TlsKeys {
        tx: tx_material,
        rx: rx_material,
    })
}

/// Convert rustls extracted secrets to kTLS key material (placeholder version)
///
/// This function takes the secrets extracted from rustls via `dangerous_extract_secrets()`
/// and converts them to the format required by Linux kTLS.
///
/// Note: This is a placeholder for the actual rustls integration.
/// The real implementation would use rustls::ConnectionTrafficSecrets.
///
/// # Example (conceptual)
///
/// ```ignore
/// use rustls::ConnectionTrafficSecrets;
///
/// let tls_stream = connector.connect(domain, tcp_stream).await?;
/// let (tcp_stream, connection) = tls_stream.into_inner();
/// let secrets = connection.dangerous_extract_secrets()?;
///
/// let keys = convert_rustls_secrets(&secrets)?;
/// ```
pub fn convert_rustls_secrets_placeholder(
    tx_seq: u64,
    rx_seq: u64,
    cipher_suite: u16,
    tx_key: &[u8],
    tx_iv: &[u8],
    rx_key: &[u8],
    rx_iv: &[u8],
) -> Result<TlsKeys> {
    // Validate key and IV lengths based on cipher suite
    let (expected_key_len, expected_iv_len) = match cipher_suite {
        0x1301 | 0x1302 => (32, 12), // AES-128-GCM / AES-256-GCM
        0x1303 => (32, 12),           // ChaCha20-Poly1305
        _ => return Err(KtlsError::KeyExtraction(format!(
            "Unsupported cipher suite: 0x{:04x}",
            cipher_suite
        ))),
    };

    if tx_key.len() < expected_key_len || rx_key.len() < expected_key_len {
        return Err(KtlsError::KeyExtraction(format!(
            "Invalid key length. Expected at least {}, got tx={}, rx={}",
            expected_key_len,
            tx_key.len(),
            rx_key.len()
        )));
    }

    if tx_iv.len() < expected_iv_len || rx_iv.len() < expected_iv_len {
        return Err(KtlsError::KeyExtraction(format!(
            "Invalid IV length. Expected at least {}, got tx={}, rx={}",
            expected_iv_len,
            tx_iv.len(),
            rx_iv.len()
        )));
    }

    let tx_material = KeyMaterial {
        tls_version: 0x0304, // TLS 1.3
        cipher_suite,
        key: tx_key.to_vec(),
        iv: tx_iv.to_vec(),
        seq: tx_seq,
    };

    let rx_material = KeyMaterial {
        tls_version: 0x0304, // TLS 1.3
        cipher_suite,
        key: rx_key.to_vec(),
        iv: rx_iv.to_vec(),
        seq: rx_seq,
    };

    Ok(TlsKeys {
        tx: tx_material,
        rx: rx_material,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_mock_key_extraction() {
        let extractor = KeyExtractor::new(KeyExtractionStrategy::Mock);
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9090);

        let keys = extractor.extract_keys(local, remote, true).await;
        assert!(keys.is_ok());
    }

    #[tokio::test]
    async fn test_preshared_key_extraction() {
        let manager = Arc::new(KeyManager::new());
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9090);
        let conn_id = ConnectionId::new(local, remote);

        // Store test keys
        let keys = TlsKeys {
            tx: KeyMaterial::new(0x0304, 0x1301, vec![1, 2, 3, 4], vec![5, 6, 7, 8]),
            rx: KeyMaterial::new(0x0304, 0x1301, vec![9, 10, 11, 12], vec![13, 14, 15, 16]),
        };
        manager.store_keys(conn_id.clone(), keys).await;

        // Extract keys
        let extracted = extract_keys_from_connection(manager, local, remote, true).await;
        assert!(extracted.is_ok());
    }
}
