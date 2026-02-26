// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Software implementations of engines.

#[cfg(feature = "sw_integrity")]
mod integrity;

#[cfg(feature = "sw_integrity")]
pub use integrity::SwIntegrityEngine;

#[cfg(feature = "sw_crypto")]
mod crypto;

#[cfg(feature = "sw_crypto")]
pub use crypto::SwCryptoEngine;
