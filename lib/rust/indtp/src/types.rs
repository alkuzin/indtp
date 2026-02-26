// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Types and types aliases used across the crate.

use crate::prelude::*;
use core::{
    error,
    fmt::{Display, Formatter},
    result,
};

/// Protocol errors enumeration.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Error to convert from/to bytes.
    ParseError,
    /// Buffer too short.
    BufferUnderflow,
    /// Buffer too large.
    BufferOverflow,
    /// Incorrect Cyclic Redundancy Check.
    IncorrectCrc,
    /// Missing cryptographic keys.
    MissingKeys,
    /// Authentication failed.
    AuthFailed,
    /// Cryptographic error.
    CryptoError,
}

impl Display for Error {
    /// Formats the value using the given formatter.
    ///
    /// # Parameters
    /// - `f` - given formatter to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Formatting errors.
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl error::Error for Error {}

/// Result alias for INDTP.
pub type Result<T> = result::Result<T, Error>;

/// Trait for serializable & deserializable data.
pub trait Data: IntoBytes + FromBytes + Immutable + KnownLayout {}

/// Every type that has these traits also has `Data`.
impl<T: IntoBytes + FromBytes + Immutable + KnownLayout> Data for T {}

pub trait Packable: Sized + Data {
    /// Get size in bytes.
    ///
    /// # Returns
    /// - Object size in bytes.
    #[inline]
    fn size(&self) -> usize {
        size_of::<Self>()
    }

    /// Construct self from raw bytes.
    ///
    /// # Parameters
    /// - `data` - given raw bytes to handle.
    ///
    /// # Returns
    /// - New object in case of success.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Parse error.
    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < size_of::<Self>() {
            return Err(Error::BufferUnderflow);
        }

        if let Ok(payload) = Self::read_from_prefix(data) {
            Ok(payload.0)
        } else {
            Err(Error::ParseError)
        }
    }

    /// Convert object to bytes.
    ///
    /// # Returns
    /// - Bytes representation of object.
    #[inline]
    fn to_bytes(&self) -> &[u8] {
        Self::as_bytes(self)
    }
}

/// AES-128 key type alias.
pub type AesKey = [u8; 16];

/// HMAC-SHA256 key type alias.
pub type HmacKey = [u8; 32];

/// Container for cryptographic keys.
pub struct CryptoKeys {
    /// AES-128 key.
    pub aes_key: AesKey,
    /// HMAC-SHA256 key.
    pub hmac_key: HmacKey,
}

impl CryptoKeys {
    /// Construct new container for cryptographic keys.
    ///
    /// # Parameters
    /// - `aes_key` - given AES key to store.
    /// - `hmac_key` - given HMAC key to store.
    pub fn new(aes_key: AesKey, hmac_key: HmacKey) -> Self {
        Self { aes_key, hmac_key }
    }
}
