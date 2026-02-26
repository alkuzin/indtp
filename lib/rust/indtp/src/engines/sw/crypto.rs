// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Cryptography engine related declarations.

use crate::prelude::*;
#[cfg(feature = "sw_crypto")]
use aes::Aes128;
#[cfg(feature = "sw_crypto")]
use cmac::{Cmac, Mac};
#[cfg(feature = "sw_crypto")]
use ctr::{
    Ctr128BE,
    cipher::{KeyIvInit, StreamCipher},
};
#[cfg(feature = "sw_crypto")]
use hmac::Hmac;
#[cfg(feature = "sw_crypto")]
use sha2::Sha256;

#[cfg(feature = "sw_crypto")]
/// Software implementation of cryptography engine.
#[derive(Default)]
pub struct SwCryptoEngine;

#[cfg(feature = "sw_crypto")]
impl CryptographyEngine for SwCryptoEngine {
    fn compute_cmac(
        key: &AesKey,
        data: &[u8],
        out: &mut [u8; 8],
    ) -> Result<()> {
        let mut mac = Cmac::<Aes128>::new_from_slice(key.as_ref())
            .map_err(|_| Error::CryptoError)?;

        mac.update(data);

        let result = mac.finalize().into_bytes();
        let result = result.get(0..8).ok_or(Error::ParseError)?;

        out.copy_from_slice(result);
        Ok(())
    }

    fn compute_hmac(
        key: &HmacKey,
        data: &[u8],
        out: &mut [u8; 32],
    ) -> Result<()> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref())
            .map_err(|_| Error::CryptoError)?;

        mac.update(data);
        let result = mac.finalize().into_bytes();

        out.copy_from_slice(&result);
        Ok(())
    }

    fn compute_aes_ctr(
        key: &AesKey,
        nonce: &[u8],
        data: &mut [u8],
    ) -> Result<()> {
        if nonce.len() != 12 {
            return Err(Error::CryptoError);
        }

        let mut cipher =
            Ctr128BE::<Aes128>::new_from_slices(key.as_ref(), nonce)
                .map_err(|_| Error::CryptoError)?;

        cipher.apply_keystream(data);
        Ok(())
    }
}
