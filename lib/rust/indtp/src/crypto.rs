// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Cryptography engine related declarations.

#[cfg(feature = "sw_crypto")]
use aes::Aes128;
#[cfg(feature = "sw_crypto")]
use cmac::{Cmac, Mac};
#[cfg(feature = "sw_crypto")]
use ctr::{cipher::{KeyIvInit, StreamCipher}, Ctr128BE};
#[cfg(feature = "sw_crypto")]
use hmac::Hmac;
#[cfg(feature = "sw_crypto")]
use sha2::Sha256;

use crate::prelude::*;

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
    fn compute_aes_ctr(key: &AesKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        unimplemented!(
            "Missing AES-128-CTR implementation for this cryptography engine."
        );
    }
}

#[cfg(feature = "sw_crypto")]
#[derive(Default)]
/// Software implementation of cryptography engine.
pub struct SwCryptoEngine;

#[cfg(feature = "sw_crypto")]
impl CryptographyEngine for SwCryptoEngine {
    fn compute_cmac(key: &AesKey, data: &[u8], out: &mut [u8; 8]) -> Result<()> {
        let mut mac = Cmac::<Aes128>::new_from_slice(key.as_ref())
            .map_err(|_| Error::CryptoError)?;

        mac.update(data);
        let result = mac.finalize().into_bytes();

        out.copy_from_slice(&result[0..8]);
        Ok(())
    }

    fn compute_hmac(key: &HmacKey, data: &[u8], out: &mut [u8; 32]) -> Result<()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref())
            .map_err(|_| Error::CryptoError)?;

        mac.update(data);
        let result = mac.finalize().into_bytes();

        out.copy_from_slice(&result);
        Ok(())
    }

    fn compute_aes_ctr(key: &AesKey, nonce: &[u8], data: &mut [u8]) -> Result<()> {
        if nonce.len() != 12 {
            return Err(Error::CryptoError);
        }

        let mut cipher = Ctr128BE::<Aes128>::new_from_slices(key.as_ref(), nonce)
            .map_err(|_| Error::CryptoError)?;

        cipher.apply_keystream(data);
        Ok(())
    }
}
