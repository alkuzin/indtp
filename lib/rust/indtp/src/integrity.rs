// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Integrity checking engine related declarations.

#[cfg(feature = "sw_integrity")]
use crc::{Crc, CRC_16_MCRF4XX, CRC_32_AUTOSAR};

/// Trait for both software & hardware-assisted integrity checking engine.
pub trait IntegrityEngine: Default {
    /// Calculating `CRC-16` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-16` value in **Little-Endian** byte order.
    fn compute_crc16(_data: &[u8]) -> u16 {
        unimplemented!(
            "Missing CRC-16 implementation for this integrity checking engine."
        );
    }

    /// Calculating `CRC-32` for given data.
    ///
    /// # Parameters
    /// - `data` - given data to handle.
    ///
    /// # Returns
    /// - `CRC-32` value in **Little-Endian** byte order.
    fn compute_crc32(_data: &[u8]) -> u32 {
        unimplemented!(
            "Missing CRC-32 implementation for this integrity checking engine."
        );
    }
}

#[cfg(feature = "sw_integrity")]
/// Software implementation of integrity checking engine.
#[derive(Default)]
pub struct SwIntegrityEngine;

#[cfg(feature = "sw_integrity")]
impl IntegrityEngine for SwIntegrityEngine {
    fn compute_crc16(data: &[u8]) -> u16 {
        Crc::<u16>::new(&CRC_16_MCRF4XX).checksum(data)
    }

    fn compute_crc32(data: &[u8]) -> u32 {
        Crc::<u32>::new(&CRC_32_AUTOSAR).checksum(data)
    }
}
