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

//! Linux-specific kTLS implementation

use super::{KeyMaterial, KtlsError, Result};
use std::os::unix::io::AsRawFd;
use tokio::net::TcpStream;
use tracing::{debug, trace};

// Linux kernel constants for kTLS
const SOL_TLS: libc::c_int = 282;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_1_3_VERSION: u16 = 0x0304;

// Cipher suite types for Linux kTLS
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

// Key sizes
const TLS_CIPHER_AES_GCM_128_KEY_SIZE: usize = 16;
const TLS_CIPHER_AES_GCM_256_KEY_SIZE: usize = 32;
const TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE: usize = 32;

const TLS_CIPHER_AES_GCM_128_IV_SIZE: usize = 8;
const TLS_CIPHER_AES_GCM_256_IV_SIZE: usize = 8;
const TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE: usize = 12;

const TLS_CIPHER_AES_GCM_128_SALT_SIZE: usize = 4;
const TLS_CIPHER_AES_GCM_256_SALT_SIZE: usize = 4;
const TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE: usize = 0;

/// Check if kTLS is supported on this Linux kernel
pub fn is_ktls_supported() -> bool {
    // Try to check if TLS module is loaded
    // This is a simple check - in production, we might want more sophisticated detection
    std::path::Path::new("/proc/sys/net/tls").exists()
}

/// Configure kTLS for TX (transmit)
pub fn configure_ktls_tx(stream: &TcpStream, key_material: &KeyMaterial) -> Result<()> {
    configure_ktls_direction(stream, key_material, TLS_TX)
}

/// Configure kTLS for RX (receive)
pub fn configure_ktls_rx(stream: &TcpStream, key_material: &KeyMaterial) -> Result<()> {
    configure_ktls_direction(stream, key_material, TLS_RX)
}

/// Configure kTLS for a specific direction (TX or RX)
fn configure_ktls_direction(
    stream: &TcpStream,
    key_material: &KeyMaterial,
    direction: libc::c_int,
) -> Result<()> {
    let fd = stream.as_raw_fd();

    // Validate TLS version
    if key_material.tls_version != TLS_1_3_VERSION {
        return Err(KtlsError::Config(format!(
            "Only TLS 1.3 is supported, got version: 0x{:04x}",
            key_material.tls_version
        )));
    }

    trace!(
        "Configuring kTLS {} for fd {} with cipher suite 0x{:04x}",
        if direction == TLS_TX { "TX" } else { "RX" },
        fd,
        key_material.cipher_suite
    );

    // Determine cipher type and validate key sizes
    let (cipher_type, key_size, iv_size, _salt_size) =
        get_cipher_params(key_material.cipher_suite)?;

    // Validate key and IV sizes
    if key_material.key.len() != key_size {
        return Err(KtlsError::Config(format!(
            "Invalid key size: expected {}, got {}",
            key_size,
            key_material.key.len()
        )));
    }

    if key_material.iv.len() < iv_size {
        return Err(KtlsError::Config(format!(
            "Invalid IV size: expected at least {}, got {}",
            iv_size,
            key_material.iv.len()
        )));
    }

    // Build the crypto info structure based on cipher type
    let result = match cipher_type {
        TLS_CIPHER_AES_GCM_128 => configure_aes_gcm_128(fd, key_material, direction),
        TLS_CIPHER_AES_GCM_256 => configure_aes_gcm_256(fd, key_material, direction),
        TLS_CIPHER_CHACHA20_POLY1305 => {
            configure_chacha20_poly1305(fd, key_material, direction)
        }
        _ => {
            return Err(KtlsError::InvalidCipherSuite(format!(
                "Unsupported cipher type: {}",
                cipher_type
            )))
        }
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        return Err(KtlsError::SocketConfig(err));
    }

    debug!(
        "Successfully configured kTLS {} for fd {}",
        if direction == TLS_TX { "TX" } else { "RX" },
        fd
    );

    Ok(())
}

/// Get cipher parameters (type, key size, IV size, salt size)
fn get_cipher_params(cipher_suite: u16) -> Result<(u16, usize, usize, usize)> {
    match cipher_suite {
        0x1301 => Ok((
            TLS_CIPHER_AES_GCM_128,
            TLS_CIPHER_AES_GCM_128_KEY_SIZE,
            TLS_CIPHER_AES_GCM_128_IV_SIZE,
            TLS_CIPHER_AES_GCM_128_SALT_SIZE,
        )),
        0x1302 => Ok((
            TLS_CIPHER_AES_GCM_256,
            TLS_CIPHER_AES_GCM_256_KEY_SIZE,
            TLS_CIPHER_AES_GCM_256_IV_SIZE,
            TLS_CIPHER_AES_GCM_256_SALT_SIZE,
        )),
        0x1303 => Ok((
            TLS_CIPHER_CHACHA20_POLY1305,
            TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE,
            TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE,
            TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE,
        )),
        _ => Err(KtlsError::InvalidCipherSuite(format!(
            "Unknown TLS 1.3 cipher suite: 0x{:04x}",
            cipher_suite
        ))),
    }
}

// Note: The following functions use repr(C) structures that match the Linux kernel ABI
// These are simplified representations. In production, you would need exact kernel structures.

#[repr(C)]
struct TlsCryptoInfoAesGcm128 {
    version: u16,
    cipher_type: u16,
    iv: [u8; TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_SALT_SIZE],
    key: [u8; TLS_CIPHER_AES_GCM_128_KEY_SIZE],
    salt: [u8; TLS_CIPHER_AES_GCM_128_SALT_SIZE],
    rec_seq: [u8; 8],
}

fn configure_aes_gcm_128(fd: i32, key_material: &KeyMaterial, direction: i32) -> i32 {
    let mut crypto_info = TlsCryptoInfoAesGcm128 {
        version: TLS_1_3_VERSION,
        cipher_type: TLS_CIPHER_AES_GCM_128,
        iv: [0; TLS_CIPHER_AES_GCM_128_IV_SIZE + TLS_CIPHER_AES_GCM_128_SALT_SIZE],
        key: [0; TLS_CIPHER_AES_GCM_128_KEY_SIZE],
        salt: [0; TLS_CIPHER_AES_GCM_128_SALT_SIZE],
        rec_seq: [0; 8],
    };

    // Copy key
    crypto_info.key[..key_material.key.len()].copy_from_slice(&key_material.key);

    // Copy IV (first 8 bytes are the IV, next 4 bytes are the salt for AES-GCM)
    let iv_len = std::cmp::min(key_material.iv.len(), crypto_info.iv.len());
    crypto_info.iv[..iv_len].copy_from_slice(&key_material.iv[..iv_len]);

    // Set sequence number
    crypto_info.rec_seq = key_material.seq.to_be_bytes();

    unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            &crypto_info as *const _ as *const libc::c_void,
            std::mem::size_of::<TlsCryptoInfoAesGcm128>() as libc::socklen_t,
        )
    }
}

#[repr(C)]
struct TlsCryptoInfoAesGcm256 {
    version: u16,
    cipher_type: u16,
    iv: [u8; TLS_CIPHER_AES_GCM_256_IV_SIZE + TLS_CIPHER_AES_GCM_256_SALT_SIZE],
    key: [u8; TLS_CIPHER_AES_GCM_256_KEY_SIZE],
    salt: [u8; TLS_CIPHER_AES_GCM_256_SALT_SIZE],
    rec_seq: [u8; 8],
}

fn configure_aes_gcm_256(fd: i32, key_material: &KeyMaterial, direction: i32) -> i32 {
    let mut crypto_info = TlsCryptoInfoAesGcm256 {
        version: TLS_1_3_VERSION,
        cipher_type: TLS_CIPHER_AES_GCM_256,
        iv: [0; TLS_CIPHER_AES_GCM_256_IV_SIZE + TLS_CIPHER_AES_GCM_256_SALT_SIZE],
        key: [0; TLS_CIPHER_AES_GCM_256_KEY_SIZE],
        salt: [0; TLS_CIPHER_AES_GCM_256_SALT_SIZE],
        rec_seq: [0; 8],
    };

    // Copy key
    crypto_info.key[..key_material.key.len()].copy_from_slice(&key_material.key);

    // Copy IV
    let iv_len = std::cmp::min(key_material.iv.len(), crypto_info.iv.len());
    crypto_info.iv[..iv_len].copy_from_slice(&key_material.iv[..iv_len]);

    // Set sequence number
    crypto_info.rec_seq = key_material.seq.to_be_bytes();

    unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            &crypto_info as *const _ as *const libc::c_void,
            std::mem::size_of::<TlsCryptoInfoAesGcm256>() as libc::socklen_t,
        )
    }
}

#[repr(C)]
struct TlsCryptoInfoChaCha20Poly1305 {
    version: u16,
    cipher_type: u16,
    iv: [u8; TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE],
    key: [u8; TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE],
    rec_seq: [u8; 8],
}

fn configure_chacha20_poly1305(fd: i32, key_material: &KeyMaterial, direction: i32) -> i32 {
    let mut crypto_info = TlsCryptoInfoChaCha20Poly1305 {
        version: TLS_1_3_VERSION,
        cipher_type: TLS_CIPHER_CHACHA20_POLY1305,
        iv: [0; TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE],
        key: [0; TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE],
        rec_seq: [0; 8],
    };

    // Copy key
    crypto_info.key[..key_material.key.len()].copy_from_slice(&key_material.key);

    // Copy IV
    let iv_len = std::cmp::min(key_material.iv.len(), crypto_info.iv.len());
    crypto_info.iv[..iv_len].copy_from_slice(&key_material.iv[..iv_len]);

    // Set sequence number
    crypto_info.rec_seq = key_material.seq.to_be_bytes();

    unsafe {
        libc::setsockopt(
            fd,
            SOL_TLS,
            direction,
            &crypto_info as *const _ as *const libc::c_void,
            std::mem::size_of::<TlsCryptoInfoChaCha20Poly1305>() as libc::socklen_t,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_params() {
        let (cipher_type, key_size, iv_size, _) = get_cipher_params(0x1301).unwrap();
        assert_eq!(cipher_type, TLS_CIPHER_AES_GCM_128);
        assert_eq!(key_size, 16);
        assert_eq!(iv_size, 8);

        let (cipher_type, key_size, iv_size, _) = get_cipher_params(0x1302).unwrap();
        assert_eq!(cipher_type, TLS_CIPHER_AES_GCM_256);
        assert_eq!(key_size, 32);
        assert_eq!(iv_size, 8);
    }

    #[test]
    fn test_invalid_cipher() {
        assert!(get_cipher_params(0xFFFF).is_err());
    }
}
