// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Types and types aliases used across the crate.

use core::{error, result, fmt::{Display, Formatter}};
use crate::prelude::*;

/// Protocol errors enumeration.
#[derive(Debug)]
pub enum Error {
    /// Error to convert from/to bytes.
    ParseError,
    /// Buffer too short.
    BufferUnderflow,
    /// Buffer too large.
    BufferOverflow,
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
