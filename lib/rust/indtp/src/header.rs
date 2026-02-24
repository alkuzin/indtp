// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP header related declarations.

use core::ops::Range;
use crate::{
    utils::{change_bit, test_bit, create_mask, get_bit_field, set_bit_field},
    prelude::*, indtp_data
};

/// Protocol operating mode enumeration. Each mode dictates the integrity check
/// algorithm and the trailer section structure.
#[derive(Debug, PartialEq, Copy, Clone)]
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
    /// Convert protocol operating mode to u8.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to convert.
    ///
    /// # Returns
    /// - Protocol operating mode in u8 representation.
    fn from(mode: Mode) -> Self {
        mode as Self
    }
}

impl TryFrom<u8> for Mode {
    /// The type returned in the event of a conversion error.
    type Error = Error;

    /// Try to convert byte to IDTP mode.
    ///
    /// # Parameters
    /// - `byte` - given byte to convert.
    ///
    /// # Returns
    /// - IDTP mode from byte - in case of success.
    /// - Error otherwise.
    ///
    /// # Errors
    /// - Parse Error.
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

/// Batching flag:
/// - `0`: Single sample mode. Payload contains one data record with
/// an absolute timestamp;
/// - `1`: Batch mode. Payload section starts with count `N`, followed by
/// `N` records with relative timestamps.
const FLAG_BATCH: u8 = 3;

/// Payload encryption flag:
/// - `0`: Payload is not encrypted;
/// - `1`: Payload is encrypted using `AES-128-CTR`.
const FLAG_ENCRYPT: u8 = 4;

/// Frame handling priority flag:
/// - `0`: Low priority.
/// - `1`: High priority.
const FLAG_PRIORITY: u8 = 5;

/// Payload mode bit mask.
const MODE_MASK: u8 = create_mask(2, 0);

/// Magic number signaling the start of a new INDTP frame.
pub const INDTP_PREAMBLE: u32 = 0x54444E49;

/// Protocol version encoded as `MMMMmmmm` (4 bits Major, 4 bits Minor).
pub const INDTP_VERSION: u8 = 0x10;

/// Standard payload type range.
pub const STANDARD_PAYLOAD_RANGE: Range<u8> = 0x00..0x7F + 1;

/// Vendor-specific payload type range.
pub const VENDOR_PAYLOAD_RANGE: Range<u8> = 0x80..0xFF;

/// Size of INDTP header in bytes.
pub const HEADER_SIZE: usize = size_of::<Header>();

indtp_data! {
    /// Contains all necessary metadata for routing, versioning, and initial
    /// integrity checking.
    #[derive(Default)]
    pub struct Header {
        /// Magic number signaling the start of a new frame.
        pub preamble: u32,
        /// Protocol version encoded as `MMMMmmmm` (4 bits Major, 4 bits Minor).
        pub version: u8,
        /// Bitmask controlling protocol behavior and frame structure.
        pub flags: u8,
        /// Unique identifier of the source navigation node.
        pub device_id: u8,
        /// Identifier defining the structure and semantics of the payload data.
        pub payload_type: u8,
        /// Monotonically increasing value used for detecting
        /// lost packets & preventing replay attacks.
        pub sequence: u16,
        /// Size of the payload section in bytes.
        pub payload_len: u16,
        /// Cyclic Redundancy Check for header integrity.
        pub crc: u16,
    }
}

impl Header {
    /// Construct new INDTP header.
    ///
    /// # Returns
    /// - New INDTP header.
    pub fn new() -> Self {
        Self {
            preamble: INDTP_PREAMBLE,
            version: INDTP_VERSION,
            ..Default::default()
        }
    }

    /// Set protocol operating mode.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to set.
    pub fn set_mode(&mut self, mode: Mode) {
        let mode = u8::from(mode);
        set_bit_field(&mut self.flags, MODE_MASK, mode);
    }

    /// Get protocol operating mode.
    ///
    /// # Returns
    /// - Protocol operating mode - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse error.
    pub fn mode(&self) -> Result<Mode> {
        let mode = get_bit_field(self.flags, MODE_MASK);
        Mode::try_from(mode)
    }

    /// Check whether data aggregation is enabled or not for payload.
    ///
    /// # Returns
    /// - `true` - if batch mode is enabled.
    /// - `false` - if single sample mode is enabled.
    pub fn is_batch(&self) -> bool {
        test_bit(self.flags, FLAG_BATCH)
    }

    /// Enable/disable data aggregation for payload.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    pub fn set_batch(&mut self, enabled: bool) {
        change_bit(&mut self.flags, FLAG_BATCH, enabled);
    }

    /// Check whether payload is encrypted or not.
    ///
    /// # Returns
    /// - `true` - if payload is encrypted.
    /// - `false` - if payload is plaintext.
    pub fn is_encrypted(&self) -> bool {
        test_bit(self.flags, FLAG_ENCRYPT)
    }

    /// Set/unset payload encryption flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    pub fn set_encrypted(&mut self, enabled: bool) {
        change_bit(&mut self.flags, FLAG_ENCRYPT, enabled);
    }

    /// Check whether frame handling has high priority.
    ///
    /// # Returns
    /// - `true` - if frame handling has high priority.
    /// - `false` - if frame handling has low priority.
    pub fn is_high_priority(&self) -> bool {
        test_bit(self.flags, FLAG_PRIORITY)
    }

    /// Set frame handling priority.
    ///
    /// # Parameters
    /// - `high` - given flag to handle.
    pub fn set_priority(&mut self, high: bool) {
        change_bit(&mut self.flags, FLAG_PRIORITY, high);
    }

    /// Check whether payload is standard or not.
    ///
    /// # Returns
    /// - `true` - if payload type is standard.
    /// - `false` - if payload type is vendor-specific.
    pub fn is_standard_payload(&self) -> bool {
        STANDARD_PAYLOAD_RANGE.contains(&(self.payload_type))
    }

    /// Get header size.
    ///
    /// # Returns
    /// - Header size in bytes.
    #[inline]
    #[must_use]
    pub const fn size() -> usize {
        HEADER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indtp_set_and_get_mode() {
        let mut header = Header::new();

        let mode = Mode::Lite;
        header.set_mode(mode);
        assert_eq!(mode, header.mode().unwrap());

        let mode = Mode::Verified;
        header.set_mode(mode);
        assert_eq!(mode, header.mode().unwrap());

        let mode = Mode::Trusted;
        header.set_mode(mode);
        assert_eq!(mode, header.mode().unwrap());

        let mode = Mode::Critical;
        header.set_mode(mode);
        assert_eq!(mode, header.mode().unwrap());
    }

    #[test]
    fn test_indtp_set_and_get_batch() {
        let mut header = Header::new();

        let state = true;
        header.set_batch(state);
        assert_eq!(state, header.is_batch());

        let state = false;
        header.set_batch(state);
        assert_eq!(state, header.is_batch());
    }

    #[test]
    fn test_indtp_set_and_get_encrypted() {
        let mut header = Header::new();

        let state = true;
        header.set_encrypted(state);
        assert_eq!(state, header.is_encrypted());

        let state = false;
        header.set_encrypted(state);
        assert_eq!(state, header.is_encrypted());
    }

    #[test]
    fn test_indtp_set_and_get_priority() {
        let mut header = Header::new();

        let state = true;
        header.set_priority(state);
        assert_eq!(state, header.is_high_priority());

        let state = false;
        header.set_priority(state);
        assert_eq!(state, header.is_high_priority());
    }

    #[test]
    fn test_indtp_payload_type() {
        let mut header = Header::new();

        header.payload_type = 0x00;
        assert!(header.is_standard_payload());

        header.payload_type = 0x12;
        assert!(header.is_standard_payload());

        header.payload_type = 0x7E;
        assert!(header.is_standard_payload());

        header.payload_type = 0x7F;
        assert!(header.is_standard_payload());

        header.payload_type = 0x80;
        assert!(!header.is_standard_payload());

        header.payload_type = 0x9F;
        assert!(!header.is_standard_payload());

        header.payload_type = 0xFF;
        assert!(!header.is_standard_payload());
    }
}
