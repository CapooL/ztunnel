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

//! kTLS integration helpers for proxy module
//!
//! This module provides helper functions to integrate kTLS with the proxy's
//! TLS connections, allowing for kernel-level encryption offload while
//! preserving the original socket connection.

use crate::ktls::{KtlsConnection, KtlsMode, convert_rustls_secrets};
use crate::config::Config;
use tokio::net::TcpStream;
use tokio_rustls::client;
use tracing::{debug, info, warn};
use std::io;

/// Configure kTLS for an outbound TLS connection if enabled in config
///
/// This function takes a TLS stream after the handshake is complete,
/// extracts the keys, and configures kTLS on the underlying TCP socket.
///
/// # Arguments
///
/// * `tls_stream` - The established TLS stream
/// * `config` - The ztunnel configuration
///
/// # Returns
///
/// Returns the underlying TCP stream with kTLS configured, or the original
/// TLS stream if kTLS is disabled or fails.
pub async fn configure_ktls_outbound(
    tls_stream: client::TlsStream<TcpStream>,
    config: &Config,
) -> Result<TcpStream, io::Error> {
    // Check if kTLS is enabled for outbound
    if !config.ktls_config.enabled || !config.ktls_config.outbound_enabled {
        debug!("kTLS not enabled for outbound, using standard TLS");
        // We can't easily return the TLS stream, so we need to handle this differently
        // For now, return an error indicating we can't proceed without kTLS support
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kTLS is not enabled, cannot extract underlying TCP stream",
        ));
    }

    info!("Configuring kTLS for outbound connection");

    // Extract the underlying TCP stream and connection
    let (tcp_stream, connection) = tls_stream.into_inner();
    let local_addr = tcp_stream.local_addr()?;
    let remote_addr = tcp_stream.peer_addr()?;

    // Extract secrets from rustls connection
    let secrets = match connection.dangerous_extract_secrets() {
        Ok(secrets) => secrets,
        Err(e) => {
            warn!("Failed to extract secrets from rustls connection: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to extract TLS secrets: {:?}", e),
            ));
        }
    };

    debug!("Successfully extracted TLS secrets from rustls");

    // Convert rustls secrets to kTLS key material
    let keys = match convert_rustls_secrets(secrets) {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to convert rustls secrets to kTLS keys: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert TLS secrets: {:?}", e),
            ));
        }
    };

    debug!("Converted rustls secrets to kTLS key material");

    // Create kTLS connection
    let mut ktls_conn = match KtlsConnection::new(tcp_stream, KtlsMode::Both) {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Failed to create kTLS connection: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create kTLS connection: {:?}", e),
            ));
        }
    };

    // Configure kTLS with the extracted keys
    if let Err(e) = ktls_conn.configure_ktls(keys).await {
        warn!("Failed to configure kTLS: {:?}", e);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to configure kTLS: {:?}", e),
        ));
    }

    info!(
        "kTLS configured successfully for {}→{}",
        local_addr, remote_addr
    );

    // Return the underlying TCP stream with kTLS configured
    Ok(ktls_conn.into_stream())
}

/// Configure kTLS for an inbound TLS connection if enabled in config
///
/// This function takes a TLS stream after the handshake is complete,
/// extracts the keys, and configures kTLS on the underlying TCP socket.
///
/// # Arguments
///
/// * `tls_stream` - The established TLS stream
/// * `config` - The ztunnel configuration
///
/// # Returns
///
/// Returns the underlying TCP stream with kTLS configured, or an error.
pub async fn configure_ktls_inbound(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    config: &Config,
) -> Result<TcpStream, io::Error> {
    // Check if kTLS is enabled for inbound
    if !config.ktls_config.enabled || !config.ktls_config.inbound_enabled {
        debug!("kTLS not enabled for inbound, using standard TLS");
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "kTLS is not enabled, cannot extract underlying TCP stream",
        ));
    }

    info!("Configuring kTLS for inbound connection");

    // Extract the underlying TCP stream and connection
    let (tcp_stream, connection) = tls_stream.into_inner();
    let local_addr = tcp_stream.local_addr()?;
    let remote_addr = tcp_stream.peer_addr()?;

    // Extract secrets from rustls connection
    let secrets = match connection.dangerous_extract_secrets() {
        Ok(secrets) => secrets,
        Err(e) => {
            warn!("Failed to extract secrets from rustls connection: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to extract TLS secrets: {:?}", e),
            ));
        }
    };

    debug!("Successfully extracted TLS secrets from rustls");

    // Convert rustls secrets to kTLS key material
    let keys = match convert_rustls_secrets(secrets) {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to convert rustls secrets to kTLS keys: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to convert TLS secrets: {:?}", e),
            ));
        }
    };

    debug!("Converted rustls secrets to kTLS key material");

    // Create kTLS connection
    let mut ktls_conn = match KtlsConnection::new(tcp_stream, KtlsMode::Both) {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Failed to create kTLS connection: {:?}", e);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create kTLS connection: {:?}", e),
            ));
        }
    };

    // Configure kTLS with the extracted keys
    if let Err(e) = ktls_conn.configure_ktls(keys).await {
        warn!("Failed to configure kTLS: {:?}", e);
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to configure kTLS: {:?}", e),
        ));
    }

    info!(
        "kTLS configured successfully for {}←{}",
        local_addr, remote_addr
    );

    // Return the underlying TCP stream with kTLS configured
    Ok(ktls_conn.into_stream())
}
