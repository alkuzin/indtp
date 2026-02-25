// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP header related declarations.

use core::ops::Range;
use bitflags::bitflags;
use zerocopy::little_endian::{U16, U32};
use crate::{
    prelude::*, integrity::IntegrityChecker, types::Packable, indtp_data,
};

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

bitflags! {
    /// Protocol flags type-safe wrapper.
    #[derive(PartialEq, Eq)]
    pub struct Flags: u8 {
        /// Mode for minimum latency and overhead for trusted internal channels.
        const MODE_LITE = 0b0000_0000;

        /// Robust data transmission in noisy environments with protection against
        /// accidental corruption.
        const MODE_VERIFIED = 0b0000_0001;

        /// Balanced security for unsecured wireless channels.
        /// Provides protection against data spoofing and replay attacks with
        /// minimal overhead.
        const MODE_TRUSTED = 0b0000_0010;

        /// Maximum security for critical commands, firmware updates, or
        /// configuration changes where bandwidth is secondary to trust.
        const MODE_CRITICAL = 0b0000_0011;

        /// Payload mode bit mask.
        const MODE_MASK = 0b0000_0011;

        /// Batching flag:
        /// - `0`: Single sample mode. Payload contains one data record with
        /// an absolute timestamp;
        /// - `1`: Batch mode. Payload section starts with count `N`, followed by
        /// `N` records with relative timestamps.
        const BATCH = 1 << 2;

        /// Payload encryption flag:
        /// - `0`: Payload is not encrypted;
        /// - `1`: Payload is encrypted using `AES-128-CTR`.
        const ENCRYPT = 1 << 3;

        /// Frame handling priority flag:
        /// - `0`: Low priority.
        /// - `1`: High priority.
        const PRIORITY = 1 << 4;
    }
}

/// Protocol version encoded as `MMMMmmmm` (4 bits Major, 4 bits Minor).
pub const INDTP_VERSION: u8 = 0x10;

/// Standard payload type range.
pub const STANDARD_PAYLOAD_RANGE: Range<u8> = 0x00..0x7F + 1;

/// Vendor-specific payload type range.
pub const VENDOR_PAYLOAD_RANGE: Range<u8> = 0x80..0xFF;

indtp_data! {
    /// Contains all necessary metadata for routing, versioning, and initial
    /// integrity checking.
    #[derive(Default)]
    pub struct Header {
        /// Magic number signaling the start of a new frame.
        pub preamble: U32,
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
        pub sequence: U16,
        /// Size of the payload section in bytes.
        pub payload_len: U16,
        /// Cyclic Redundancy Check for header integrity.
        pub crc: U16,
    }
}

impl Header {
    /// Magic number signaling the start of a new INDTP frame.
    pub const PREAMBLE: u32 = 0x54444E49;

    /// Size of INDTP header in bytes.
    pub const SIZE: usize = 14;

    /// Offset for which to calculate the CRC (0..CRC_OFFSET).
    const CRC_OFFSET: usize = 12;

    /// Construct new INDTP header.
    ///
    /// # Returns
    /// - New INDTP header.
    pub fn new() -> Self {
        Self {
            preamble: U32::new(Self::PREAMBLE),
            version: INDTP_VERSION,
            ..Default::default()
        }
    }

    /// Get protocol flags.
    ///
    /// # Returns
    /// - Protocol flags type-safe wrapper.
    #[inline]
    pub fn get_flags(&self) -> Flags {
        Flags::from_bits_truncate(self.flags)
    }

    /// Set flags from a type-safe bitflags struct.
    /// Set protocol flags.
    ///
    /// # Parameters
    /// - `flags` - given protocol flags type-safe wrapper to handle.
    #[inline]
    pub fn set_flags(&mut self, flags: Flags) {
        self.flags = flags.bits();
    }

    /// Set protocol operating mode.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to set.
    pub fn set_mode(&mut self, mode: Mode) {
        let mut flags = self.get_flags();
        flags.remove(Flags::MODE_MASK);
        flags.insert(mode.into());
        self.flags = flags.bits();
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
        let flags = self.get_flags();
        Mode::try_from(flags)
    }

    /// Check whether data aggregation is enabled or not for payload.
    ///
    /// # Returns
    /// - `true` - if batch mode is enabled.
    /// - `false` - if single sample mode is enabled.
    pub fn is_batch(&self) -> bool {
        let flags = self.get_flags();
        flags.contains(Flags::BATCH)
    }

    /// Enable/disable data aggregation for payload.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    pub fn set_batch(&mut self, enabled: bool) {
        let mut flags = self.get_flags();
        flags.set(Flags::BATCH, enabled);
        self.flags = flags.bits();
    }

    /// Check whether payload is encrypted or not.
    ///
    /// # Returns
    /// - `true` - if payload is encrypted.
    /// - `false` - if payload is plaintext.
    pub fn is_encrypted(&self) -> bool {
        let flags = self.get_flags();
        flags.contains(Flags::ENCRYPT)
    }

    /// Set/unset payload encryption flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    pub fn set_encrypted(&mut self, enabled: bool) {
        let mut flags = self.get_flags();
        flags.set(Flags::ENCRYPT, enabled);
        self.flags = flags.bits();
    }

    /// Check whether frame handling has high priority.
    ///
    /// # Returns
    /// - `true` - if frame handling has high priority.
    /// - `false` - if frame handling has low priority.
    pub fn is_high_priority(&self) -> bool {
        let flags = self.get_flags();
        flags.contains(Flags::PRIORITY)
    }

    /// Set frame handling priority.
    ///
    /// # Parameters
    /// - `high` - given flag to handle.
    pub fn set_priority(&mut self, high: bool) {
        let mut flags = self.get_flags();
        flags.set(Flags::PRIORITY, high);
        self.flags = flags.bits();
    }

    /// Check whether payload is standard or not.
    ///
    /// # Returns
    /// - `true` - if payload type is standard.
    /// - `false` - if payload type is vendor-specific.
    pub fn is_standard_payload(&self) -> bool {
        STANDARD_PAYLOAD_RANGE.contains(&(self.payload_type))
    }

    /// Calculating `CRC-16` for header.
    ///
    /// # Returns
    /// - `CRC-16` value in **Little-Endian** byte order.
    #[inline]
    fn compute_crc(&self) -> Result<u16> {
        let data = &self.as_bytes()
            .get(0..Self::CRC_OFFSET)
            .ok_or(Error::ParseError)?;

        Ok(IntegrityEngine::compute_crc16(&data))
    }

    /// Pack header into raw bytes.
    ///
    /// # Returns
    /// - Packed header bytes array - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Parse errors.
    /// - Incorrect CRC.
    pub fn pack(&self) -> Result<[u8; Self::SIZE]> {
        let mut buffer = [0u8; Self::SIZE];
        self.pack_into(&mut buffer)?;
        Ok(buffer)
    }

    /// Pack header into raw bytes into specified buffer.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to put result into.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Parse errors.
    /// - Incorrect CRC.
    pub fn pack_into(&self, buffer: &mut [u8]) -> Result<()> {
        // Checking size.
        if buffer.len() < Self::SIZE {
            return Err(Error::BufferUnderflow);
        }

        buffer
            .get_mut(0..Self::SIZE)
            .ok_or(Error::ParseError)?
            .copy_from_slice(&self.as_bytes());

        let crc = self.compute_crc()?;

        buffer
            .get_mut(Self::CRC_OFFSET..Self::SIZE)
            .ok_or(Error::ParseError)?
            .copy_from_slice(&crc.to_le_bytes());

        Ok(())
    }

    /// Validate correctness of the header.
    ///
    /// # Parameters
    /// - `buffer` - given buffer with header bytes to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Parse errors.
    /// - Incorrect CRC.
    pub fn validate(buffer: &[u8]) -> Result<()> {
        // Checking size.
        if buffer.len() < Self::SIZE {
            return Err(Error::BufferUnderflow);
        }

        // Checking preamble.
        let preamble: &[u8; 4] = buffer
            .get(0..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(Error::ParseError)?;

        let preamble = u32::from_le_bytes(*preamble);

        if preamble != Self::PREAMBLE {
            return Err(Error::ParseError);
        }

        // Checking CRC.
        let data = buffer
            .get(0..Self::CRC_OFFSET)
            .ok_or(Error::ParseError)?;

        let computed_crc = IntegrityEngine::compute_crc16(&data);

        let crc_bytes: &[u8; 2] = buffer
            .get(12..14)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(Error::ParseError)?;

        let received_crc = u16::from_le_bytes(*crc_bytes);

        if computed_crc != received_crc {
            return Err(Error::IncorrectCrc);
        }

        Ok(())
    }
}

impl Packable for Header {
    fn size(&self) -> usize {
        Self::SIZE
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

    /// Auxiliary function for creating INDTP header for tests.
    fn create_test_header() -> Header {
        Header {
            preamble: U32::new(Header::PREAMBLE),
            version: INDTP_VERSION,
            flags: Mode::Trusted.into(),
            device_id: 0xAB,
            payload_type: 0x03,
            sequence: U16::new(0x1234),
            payload_len: U16::new(0x0020),
            crc: U16::new(0),
        }
    }

    #[test]
    fn test_compute_crc_consistency() {
        let header = create_test_header();

        let crc1 = header.compute_crc().expect("Failed to compute CRC 1");
        let crc2 = header.compute_crc().expect("Failed to compute CRC 2");

        assert_eq!(crc1, crc2);
        assert_ne!(crc1, 0);
    }

    #[test]
    fn test_compute_crc_changes_with_data() {
        let header1 = create_test_header();
        let mut header2 = create_test_header();

        header2.device_id = 0xFF;

        let crc1 = header1.compute_crc().expect("Failed to compute CRC 1");
        let crc2 = header2.compute_crc().expect("Failed to compute CRC 2");

        assert_ne!(crc1, crc2);
    }

    #[test]
    fn test_pack_success() {
        let header = create_test_header();
        let buffer = header.pack().expect("Error to pack");

        assert_eq!(buffer.len(), Header::SIZE);
        assert_eq!(&buffer[0..4], &[0x49, 0x4E, 0x44, 0x54]);

        let crc_val = u16::from_le_bytes([buffer[12], buffer[13]]);
        assert_ne!(crc_val, 0);

        assert_eq!(buffer[4], INDTP_VERSION);
        assert_eq!(buffer[5], 0x02);
        assert_eq!(buffer[6], 0xAB);
        assert_eq!(buffer[7], 0x03);
        assert_eq!(&buffer[8..10], &[0x34, 0x12]);
        assert_eq!(&buffer[10..12], &[0x20, 0x00]);
    }

    #[test]
    fn test_header_from_bytes() {
        let header = create_test_header();
        let buffer = header.pack().expect("Error to pack");
        assert!(Header::validate(&buffer).is_ok());

        let parsed = Header::from_bytes(&buffer).expect("Conversion failed");

        assert_eq!(parsed.preamble.get(), header.preamble.get());
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.device_id, header.device_id);
        assert_eq!(parsed.sequence.get(), header.sequence.get());
    }

    #[test]
    fn test_pack_into_success() {
        let header = create_test_header();
        let mut buffer = [0u8; Header::SIZE];

        let res = header.pack_into(&mut buffer);
        assert!(res.is_ok());

        let expected = header.pack().expect("Reference pack failed");
        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_pack_into_buffer_underflow() {
        let header = create_test_header();
        let mut buffer = [0u8; Header::SIZE - 1];

        let res = header.pack_into(&mut buffer);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::BufferUnderflow);
    }

    #[test]
    fn test_pack_into_partial_write_check() {
        let header = create_test_header();
        let mut buffer = [0xFFu8; Header::SIZE];

        header.pack_into(&mut buffer).expect("Pack failed");

        assert_ne!(buffer[0], 0xFF);
        assert_ne!(buffer[1], 0xFF);
        assert!(Header::validate(&buffer).is_ok());
    }

    #[test]
    fn test_size_method() {
        let header = Header::new();
        assert_eq!(header.size(), Header::SIZE);
    }

    #[test]
    fn test_header_validation_correct_data() {
        let header = Header::new();
        let buf = header.pack().unwrap();
        let res = Header::validate(&buf);

        assert!(res.is_ok());
    }

    #[test]
    fn test_header_validation_incorrect_data() {
        let header = Header::new();
        let mut buf = header.pack().unwrap();
        buf[10] ^= 0x01;
        let res = Header::validate(&buf);

        assert!(res.is_err());
    }

    #[test]
    fn test_header_validation_incorrect_buffer_size() {
        let buf = [0_u8; Header::SIZE - 1];
        let res = Header::validate(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_header_validation_incorrect_preamble() {
        let header = Header::new();
        let mut buf = header.pack().unwrap();
        buf[0] = 0x12;

        let res = Header::validate(&buf);
        assert!(res.is_err());
    }
}
