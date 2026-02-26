// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Cryptography & integrity checking engines related declarations.

#[cfg(any(feature = "sw_integrity", feature = "sw_crypto"))]
mod sw;
#[cfg(any(feature = "sw_integrity", feature = "sw_crypto"))]
#[allow(unused)]
pub use sw::{SwIntegrityEngine, SwCryptoEngine};

use crate::prelude::*;

/// Trait for both software & hardware-assisted integrity checking engine.
pub trait IntegrityEngine: Default {
    /// Calculating `CRC-16` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-16` value in **Little-Endian** byte order.
    fn compute_crc16(_data: &[u8]) -> u16 {
        unimplemented!(
            "Missing CRC-16 implementation for this integrity checking engine."
        );
    }

    /// Calculating `CRC-32` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-32` value in **Little-Endian** byte order.
    fn compute_crc32(_data: &[u8]) -> u32 {
        unimplemented!(
            "Missing CRC-32 implementation for this integrity checking engine."
        );
    }
}

/// Trait for both software & hardware-assisted cryptography engine.
pub trait CryptographyEngine: Default {
    /// Calculating `CMAC-AES-128` truncated to 8 bytes.
    ///
    /// # Parameters
    /// - `key` - given AES key.
    /// - `data` - given data for authentication.
    /// - `out` - given output buffer.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Cryptographic errors.
    fn compute_cmac(_key: &AesKey, _data: &[u8], _out: &mut [u8; 8]) -> Result<()> {
        unimplemented!(
            "Missing CMAC-AES-128 implementation for this cryptography engine."
        );
    }

    /// Calculating `HMAC-SHA256`.
    ///
    /// # Parameters
    /// - `key` - given HMAC key (32 bytes).
    /// - `data` - given data for authentication.
    /// - `out` - given output buffer.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Cryptographic errors.
    fn compute_hmac(_key: &HmacKey, _data: &[u8], _out: &mut [u8; 32]) -> Result<()> {
        unimplemented!(
            "Missing HMAC-SHA256 implementation for this cryptography engine."
        );
    }

    /// Encrypts or decrypts data using `AES-128` in `CTR` mode.
    ///
    /// # Parameters
    /// - `key` - given AES key.
    /// - `nonce`: given initialization vector (12 bytes).
    /// - `data` - given data to encrypt/decrypt.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Cryptographic errors.
    fn compute_aes_ctr(_key: &AesKey, _nonce: &[u8], _data: &mut [u8]) -> Result<()> {
        unimplemented!(
            "Missing AES-128-CTR implementation for this cryptography engine."
        );
    }
}
