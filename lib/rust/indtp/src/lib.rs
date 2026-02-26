// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! `Inertial Navigation Data Transfer Protocol (INDTP)` - is a lightweight,
//! binary application-layer (L7) protocol designed specifically for the
//! **Inertial Navigation Systems (INS)** and autonomous platforms.
//!
//! INDTP addresses the critical trade-off between low-latency real-time data
//! streaming, robustness against the noise, and cryptographic security.
//! The protocol features a compact fixed size header, support for data
//! aggregation in order to minimize overhead at high sampling rates,
//! and a flexible multimode security architecture.
//!
//! INDTP serves as a unified communication standard for modern navigation
//! stacks, ensuring reliable, secure, and temporally synchronized data
//! exchange under diverse operational conditions.

#![no_std]
#![warn(clippy::all, clippy::correctness, clippy::suspicious)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::todo,
    clippy::unreachable,
    missing_docs
)]

#[macro_use]
pub mod macros;
mod types;
mod header;
mod frame;
mod engines;
mod payload;

pub use header::*;
pub use frame::*;
pub use types::{Error, Result};

pub(crate) mod prelude {
    pub use zerocopy::{IntoBytes, FromBytes, Immutable, KnownLayout};
    pub use crate::{Error, Result};
    pub use crate::header::*;
    pub use crate::types::*;
    pub use crate::engines::*;
    pub use crate::payload::*;
}
