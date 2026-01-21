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

//! Key management for kTLS connections

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// TLS key material for a connection
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// TLS version (should be TLS 1.3, value 0x0304)
    pub tls_version: u16,

    /// Cipher suite code
    pub cipher_suite: u16,

    /// Encryption key
    pub key: Vec<u8>,

    /// Initialization vector / salt
    pub iv: Vec<u8>,

    /// Sequence number
    pub seq: u64,
}

impl KeyMaterial {
    /// Create new key material
    pub fn new(tls_version: u16, cipher_suite: u16, key: Vec<u8>, iv: Vec<u8>) -> Self {
        Self {
            tls_version,
            cipher_suite,
            key,
            iv,
            seq: 0,
        }
    }

    /// Zeroize sensitive data when dropping
    pub fn zeroize(&mut self) {
        self.key.fill(0);
        self.iv.fill(0);
        self.seq = 0;
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// TX and RX keys for a connection
#[derive(Clone, Debug)]
pub struct TlsKeys {
    /// Transmit (TX) key material - for sending data
    pub tx: KeyMaterial,

    /// Receive (RX) key material - for receiving data
    pub rx: KeyMaterial,
}

/// Key configuration for manual injection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// Connection 4-tuple identifier
    pub connection_id: ConnectionId,

    /// TX key (hex-encoded)
    pub tx_key: String,

    /// TX IV (hex-encoded)
    pub tx_iv: String,

    /// RX key (hex-encoded)
    pub rx_key: String,

    /// RX IV (hex-encoded)
    pub rx_iv: String,

    /// Cipher suite
    pub cipher_suite: String,
}

/// Connection identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConnectionId {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

impl ConnectionId {
    pub fn new(src_addr: SocketAddr, dst_addr: SocketAddr) -> Self {
        Self { src_addr, dst_addr }
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}→{}", self.src_addr, self.dst_addr)
    }
}

/// Key manager for storing and retrieving kTLS keys
pub struct KeyManager {
    keys: Arc<RwLock<HashMap<ConnectionId, TlsKeys>>>,
}

impl KeyManager {
    /// Create a new key manager
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store keys for a connection
    pub async fn store_keys(&self, conn_id: ConnectionId, keys: TlsKeys) {
        debug!("Storing kTLS keys for connection: {}", conn_id);
        let mut store = self.keys.write().await;
        store.insert(conn_id, keys);
    }

    /// Retrieve keys for a connection
    pub async fn get_keys(&self, conn_id: &ConnectionId) -> Option<TlsKeys> {
        let store = self.keys.read().await;
        store.get(conn_id).cloned()
    }

    /// Remove keys for a connection (when connection closes)
    pub async fn remove_keys(&self, conn_id: &ConnectionId) {
        debug!("Removing kTLS keys for connection: {}", conn_id);
        let mut store = self.keys.write().await;
        if let Some(mut keys) = store.remove(conn_id) {
            keys.tx.zeroize();
            keys.rx.zeroize();
        }
    }

    /// Import keys from external configuration
    pub async fn import_key_config(&self, config: KeyConfig) -> Result<(), String> {
        debug!("Importing key configuration for: {}", config.connection_id);

        // Parse cipher suite
        let cipher_suite = match config.cipher_suite.as_str() {
            "TLS_AES_128_GCM_SHA256" => 0x1301,
            "TLS_AES_256_GCM_SHA384" => 0x1302,
            "TLS_CHACHA20_POLY1305_SHA256" => 0x1303,
            _ => return Err(format!("Unknown cipher suite: {}", config.cipher_suite)),
        };

        // Decode hex keys
        let tx_key = hex::decode(&config.tx_key)
            .map_err(|e| format!("Failed to decode TX key: {}", e))?;
        let tx_iv = hex::decode(&config.tx_iv)
            .map_err(|e| format!("Failed to decode TX IV: {}", e))?;
        let rx_key = hex::decode(&config.rx_key)
            .map_err(|e| format!("Failed to decode RX key: {}", e))?;
        let rx_iv = hex::decode(&config.rx_iv)
            .map_err(|e| format!("Failed to decode RX IV: {}", e))?;

        // Create key material
        let keys = TlsKeys {
            tx: KeyMaterial::new(0x0304, cipher_suite, tx_key, tx_iv),
            rx: KeyMaterial::new(0x0304, cipher_suite, rx_key, rx_iv),
        };

        self.store_keys(config.connection_id, keys).await;
        Ok(())
    }

    /// Load keys from a configuration file
    pub async fn load_from_file(&self, path: &std::path::Path) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read key config file: {}", e))?;

        let configs: Vec<KeyConfig> = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse key config file: {}", e))?;

        let count = configs.len();
        for config in configs {
            if let Err(e) = self.import_key_config(config).await {
                warn!("Failed to import key config: {}", e);
            }
        }

        debug!("Loaded {} key configurations from file", count);
        Ok(count)
    }

    /// Export current keys to a configuration (for debugging/backup)
    pub async fn export_keys(&self) -> Vec<ConnectionId> {
        let store = self.keys.read().await;
        store.keys().cloned().collect()
    }

    /// Clear all stored keys
    pub async fn clear(&self) {
        debug!("Clearing all stored kTLS keys");
        let mut store = self.keys.write().await;
        for (_, mut keys) in store.drain() {
            keys.tx.zeroize();
            keys.rx.zeroize();
        }
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_key_manager_store_retrieve() {
        let manager = KeyManager::new();
        let conn_id = ConnectionId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9090),
        );

        let keys = TlsKeys {
            tx: KeyMaterial::new(0x0304, 0x1301, vec![1, 2, 3, 4], vec![5, 6, 7, 8]),
            rx: KeyMaterial::new(0x0304, 0x1301, vec![9, 10, 11, 12], vec![13, 14, 15, 16]),
        };

        manager.store_keys(conn_id.clone(), keys).await;

        let retrieved = manager.get_keys(&conn_id).await;
        assert!(retrieved.is_some());

        manager.remove_keys(&conn_id).await;
        let retrieved = manager.get_keys(&conn_id).await;
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_key_manager_clear() {
        let manager = KeyManager::new();
        let conn_id = ConnectionId::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 9090),
        );

        let keys = TlsKeys {
            tx: KeyMaterial::new(0x0304, 0x1301, vec![1, 2, 3, 4], vec![5, 6, 7, 8]),
            rx: KeyMaterial::new(0x0304, 0x1301, vec![9, 10, 11, 12], vec![13, 14, 15, 16]),
        };

        manager.store_keys(conn_id.clone(), keys).await;
        manager.clear().await;

        let retrieved = manager.get_keys(&conn_id).await;
        assert!(retrieved.is_none());
    }
}
