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
//! Since rustls doesn't expose internal keys by design, we provide multiple strategies:
//!
//! 1. Pre-shared keys from KeyManager (for testing and manual configuration)
//! 2. SSLKEYLOGFILE-based extraction (for debugging)
//! 3. Future: OpenSSL backend integration (for automatic extraction)

use crate::ktls::{KeyMaterial, KtlsError, Result, TlsKeys};
use crate::ktls::key_manager::{ConnectionId, KeyManager};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Key extraction strategy
#[derive(Debug, Clone)]
pub enum KeyExtractionStrategy {
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
    key_manager: &KeyManager,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    is_client: bool,
) -> Result<TlsKeys> {
    let extractor = KeyExtractor::with_preshared_keys(Arc::new(key_manager.clone()));
    extractor.extract_keys(local_addr, remote_addr, is_client).await
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
        let manager = KeyManager::new();
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
        let extractor = KeyExtractor::with_preshared_keys(Arc::new(manager));
        let extracted = extractor.extract_keys(local, remote, true).await;
        assert!(extracted.is_ok());
    }
}
