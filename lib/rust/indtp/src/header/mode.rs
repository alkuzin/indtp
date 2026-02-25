// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Protocol operating modes related declarations.

use crate::prelude::*;

/// Protocol operating mode enumeration. Each mode dictates the integrity check
/// algorithm and the trailer section structure.
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum Mode {
    /// Mode for minimum latency and overhead for trusted internal channels.
    ///
    /// Protected only by `crc` (`CRC-16`).
    /// Payload integrity is not guaranteed by the protocol layer.
    ///
    /// Trailer size is `0` bytes.
    Lite = 0x00,
    /// Robust data transmission in noisy environments with protection against
    /// accidental corruption.
    ///
    /// Header is protected by `CRC-16-MCRF4XX` with `0x1021` polynomial.
    /// Full frame is protected by `CRC-32-AUTOSAR` with polynomial `0xF4ACFB13`
    /// calculated over header & payload section.
    ///
    /// Trailer size is `4` bytes.
    Verified = 0x01,
    /// Balanced security for unsecured wireless channels.
    /// Provides protection against data spoofing and replay attacks with
    /// minimal overhead.
    ///
    /// Header is protected by `CRC-16-MCRF4XX` with `0x1021` polynomial.
    /// Full frame is protected by `CMAC-AES-128`.
    ///
    /// Trailer size is `8` bytes (truncated CMAC tag).
    ///
    /// Sender and receiver **MUST** share a pre-distributed 128-bit AES key.
    /// The sequence number **MUST** be included in the CMAC calculation to
    /// prevent replay attacks.
    Trusted = 0x02,
    /// Maximum security for critical commands, firmware updates, or
    /// configuration changes where bandwidth is secondary to trust.
    ///
    /// Header is protected by `CRC-16-MCRF4XX` with `0x1021` polynomial.
    /// Full frame is protected by `HMAC-SHA256`.
    ///
    /// Trailer size is `32` bytes.
    ///
    /// Sender and receiver **MUST** share a pre-distributed HMAC key.
    /// Strict sequence number validation is mandatory.
    Critical = 0x03,
}

impl From<Mode> for u8 {
    fn from(mode: Mode) -> Self {
        mode as Self
    }
}

impl TryFrom<u8> for Mode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Lite),
            0x01 => Ok(Self::Verified),
            0x02 => Ok(Self::Trusted),
            0x03 => Ok(Self::Critical),
            _ => Err(Error::ParseError),
        }
    }
}

impl From<Mode> for Flags {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Lite => Flags::MODE_LITE,
            Mode::Verified => Flags::MODE_VERIFIED,
            Mode::Trusted => Flags::MODE_TRUSTED,
            Mode::Critical => Flags::MODE_CRITICAL,
        }
    }
}

impl TryFrom<Flags> for Mode {
    type Error = Error;

    fn try_from(flags: Flags) -> Result<Self> {
        let mode_bits = flags & Flags::MODE_MASK;

        match mode_bits {
            Flags::MODE_LITE => Ok(Mode::Lite),
            Flags::MODE_VERIFIED => Ok(Mode::Verified),
            Flags::MODE_TRUSTED => Ok(Mode::Trusted),
            Flags::MODE_CRITICAL => Ok(Mode::Critical),
            _ => Err(Error::ParseError),
        }
    }
}
