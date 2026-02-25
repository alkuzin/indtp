// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Integrity checking engine related declarations.

#[cfg(feature = "software_impl")]
use crc::{Crc, CRC_16_MCRF4XX, CRC_32_AUTOSAR};

/// Trait for both software & hardware-assisted integrity checking.
pub trait IntegrityChecker {
    /// Calculating `CRC-16` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-16` value in **Little-Endian** byte order.
    fn compute_crc16(data: &[u8]) -> u16;

    /// Calculating `CRC-32` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-32` value in **Little-Endian** byte order.
    fn compute_crc32(data: &[u8]) -> u32;
}

#[cfg(feature = "software_impl")]
pub struct SoftwareIntegrity;

#[cfg(feature = "software_impl")]
impl IntegrityChecker for SoftwareIntegrity {
    fn compute_crc16(data: &[u8]) -> u16 {
        Crc::<u16>::new(&CRC_16_MCRF4XX).checksum(data)
    }

    fn compute_crc32(data: &[u8]) -> u32 {
        Crc::<u32>::new(&CRC_32_AUTOSAR).checksum(data)
    }
}

#[cfg(feature = "software_impl")]
pub type IntegrityEngine = SoftwareIntegrity;
