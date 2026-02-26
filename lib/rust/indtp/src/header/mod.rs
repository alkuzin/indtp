// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP header related declarations.

mod flags;
mod mode;

pub use flags::*;
pub use mode::*;

use zerocopy::little_endian::{U16, U32};
use core::ops::Range;
use crate::prelude::*;

/// Protocol version encoded as `MMMMmmmm` (4 bits Major, 4 bits Minor).
pub const INDTP_VERSION: u8 = 0x10;

/// Standard payload type range.
pub const STANDARD_PAYLOAD_RANGE: Range<u8> = 0x00..0x7F + 1;

/// Vendor-specific payload type range.
pub const VENDOR_PAYLOAD_RANGE: Range<u8> = 0x80..0xFF;

/// Size of INDTP header in bytes.
pub const HEADER_SIZE: usize = 14;

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
    fn compute_crc<I: IntegrityEngine>(&self) -> Result<u16> {
        let data = &self.as_bytes()
            .get(0..Self::CRC_OFFSET)
            .ok_or(Error::ParseError)?;

        Ok(I::compute_crc16(&data))
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
    pub fn pack<I: IntegrityEngine>(&self) -> Result<[u8; HEADER_SIZE]> {
        let mut buffer = [0u8; HEADER_SIZE];
        self.pack_into::<I>(&mut buffer)?;
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
    pub fn pack_into<I: IntegrityEngine>(&self, buffer: &mut [u8]) -> Result<()> {
        // Checking size.
        if buffer.len() < HEADER_SIZE {
            return Err(Error::BufferUnderflow);
        }

        buffer
            .get_mut(0..HEADER_SIZE)
            .ok_or(Error::ParseError)?
            .copy_from_slice(&self.as_bytes());

        let crc = self.compute_crc::<I>()?;

        buffer
            .get_mut(Self::CRC_OFFSET..HEADER_SIZE)
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
    pub fn validate<I: IntegrityEngine>(buffer: &[u8]) -> Result<()> {
        // Checking size.
        if buffer.len() < HEADER_SIZE {
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

        let computed_crc = I::compute_crc16(&data);

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
        HEADER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let crc1 = header.compute_crc::<SwIntegrityEngine>()
            .expect("Failed to compute CRC 1");
        let crc2 = header.compute_crc::<SwIntegrityEngine>()
            .expect("Failed to compute CRC 2");

        assert_eq!(crc1, crc2);
        assert_ne!(crc1, 0);
    }

    #[test]
    fn test_compute_crc_changes_with_data() {
        let header1 = create_test_header();
        let mut header2 = create_test_header();

        header2.device_id = 0xFF;

        let crc1 = header1.compute_crc::<SwIntegrityEngine>()
            .expect("Failed to compute CRC 1");
        let crc2 = header2.compute_crc::<SwIntegrityEngine>()
            .expect("Failed to compute CRC 2");

        assert_ne!(crc1, crc2);
    }

    #[test]
    fn test_pack_success() {
        let header = create_test_header();
        let buffer = header.pack::<SwIntegrityEngine>().expect("Error to pack");

        assert_eq!(buffer.len(), HEADER_SIZE);
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
        let buffer = header.pack::<SwIntegrityEngine>().expect("Error to pack");
        assert!(Header::validate::<SwIntegrityEngine>(&buffer).is_ok());

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
        let mut buffer = [0u8; HEADER_SIZE];

        let res = header.pack_into::<SwIntegrityEngine>(&mut buffer);
        assert!(res.is_ok());

        let expected = header.pack::<SwIntegrityEngine>()
            .expect("Reference pack failed");

        assert_eq!(buffer, expected);
    }

    #[test]
    fn test_pack_into_buffer_underflow() {
        let header = create_test_header();
        let mut buffer = [0u8; HEADER_SIZE - 1];

        let res = header.pack_into::<SwIntegrityEngine>(&mut buffer);

        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::BufferUnderflow);
    }

    #[test]
    fn test_pack_into_partial_write_check() {
        let header = create_test_header();
        let mut buffer = [0xFFu8; HEADER_SIZE];

        header.pack_into::<SwIntegrityEngine>(&mut buffer)
            .expect("Pack failed");

        assert_ne!(buffer[0], 0xFF);
        assert_ne!(buffer[1], 0xFF);
        assert!(Header::validate::<SwIntegrityEngine>(&buffer).is_ok());
    }

    #[test]
    fn test_size_method() {
        let header = Header::new();
        assert_eq!(header.size(), HEADER_SIZE);
    }

    #[test]
    fn test_header_validation_correct_data() {
        let header = Header::new();
        let buf = header.pack::<SwIntegrityEngine>().unwrap();
        let res = Header::validate::<SwIntegrityEngine>(&buf);

        assert!(res.is_ok());
    }

    #[test]
    fn test_header_validation_incorrect_data() {
        let header = Header::new();
        let mut buf = header.pack::<SwIntegrityEngine>().unwrap();
        buf[10] ^= 0x01;
        let res = Header::validate::<SwIntegrityEngine>(&buf);

        assert!(res.is_err());
    }

    #[test]
    fn test_header_validation_incorrect_buffer_size() {
        let buf = [0_u8; HEADER_SIZE - 1];
        let res = Header::validate::<SwIntegrityEngine>(&buf);
        assert!(res.is_err());
    }

    #[test]
    fn test_header_validation_incorrect_preamble() {
        let header = Header::new();
        let mut buf = header.pack::<SwIntegrityEngine>().unwrap();
        buf[0] = 0x12;

        let res = Header::validate::<SwIntegrityEngine>(&buf);
        assert!(res.is_err());
    }
}
