// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Types and types aliases used across the crate.

use core::{error, result, fmt::{Display, Formatter}};

/// Protocol errors enumeration.
#[derive(Debug)]
pub enum Error {
    /// Error to convert from/to bytes.
    ParseError,
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
