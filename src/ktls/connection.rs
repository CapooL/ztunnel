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

//! kTLS connection handling

use super::{KtlsError, Result, TlsKeys};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::{debug, info};

/// kTLS connection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KtlsMode {
    /// Only TX (transmit) offload
    TxOnly,
    /// Only RX (receive) offload
    RxOnly,
    /// Both TX and RX offload
    Both,
}

/// A TCP connection with kTLS offload
pub struct KtlsConnection {
    /// Underlying TCP stream
    stream: TcpStream,

    /// Local address
    local_addr: SocketAddr,

    /// Remote address
    remote_addr: SocketAddr,

    /// kTLS mode
    mode: KtlsMode,

    /// Whether kTLS has been configured
    configured: bool,
}

impl KtlsConnection {
    /// Create a new kTLS connection from an existing TCP stream
    pub fn new(stream: TcpStream, mode: KtlsMode) -> Result<Self> {
        let local_addr = stream.local_addr()?;
        let remote_addr = stream.peer_addr()?;

        Ok(Self {
            stream,
            local_addr,
            remote_addr,
            mode,
            configured: false,
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the kTLS mode
    pub fn mode(&self) -> KtlsMode {
        self.mode
    }

    /// Check if kTLS has been configured
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    /// Configure kTLS with the provided keys
    ///
    /// This performs the following steps:
    /// 1. Validates the keys
    /// 2. Configures the socket for kTLS
    /// 3. Sets the TX and/or RX keys in the kernel
    ///
    /// After this, the kernel will handle encryption/decryption transparently.
    pub async fn configure_ktls(&mut self, keys: TlsKeys) -> Result<()> {
        if self.configured {
            return Err(KtlsError::Config(
                "kTLS already configured for this connection".to_string(),
            ));
        }

        info!(
            "Configuring kTLS for connection {}→{} (mode: {:?})",
            self.local_addr, self.remote_addr, self.mode
        );

        #[cfg(target_os = "linux")]
        {
            use super::linux;

            // Configure TX if needed
            if matches!(self.mode, KtlsMode::TxOnly | KtlsMode::Both) {
                linux::configure_ktls_tx(&self.stream, &keys.tx)?;
                debug!("TX kTLS configured");
            }

            // Configure RX if needed
            if matches!(self.mode, KtlsMode::RxOnly | KtlsMode::Both) {
                linux::configure_ktls_rx(&self.stream, &keys.rx)?;
                debug!("RX kTLS configured");
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            return Err(KtlsError::NotSupported);
        }

        self.configured = true;
        info!("kTLS configuration complete");

        Ok(())
    }

    /// Get a reference to the underlying TCP stream
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying TCP stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume this connection and return the underlying TCP stream
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Split the connection into read and write halves
    pub fn split(self) -> (tokio::net::tcp::OwnedReadHalf, tokio::net::tcp::OwnedWriteHalf) {
        self.stream.into_split()
    }
}

impl std::fmt::Debug for KtlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KtlsConnection")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("mode", &self.mode)
            .field("configured", &self.configured)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ktls_mode() {
        assert_eq!(KtlsMode::TxOnly, KtlsMode::TxOnly);
        assert_ne!(KtlsMode::TxOnly, KtlsMode::RxOnly);
    }
}
