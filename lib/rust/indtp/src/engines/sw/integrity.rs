// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Integrity checking engine related declarations.

#[cfg(feature = "sw_integrity")]
use crc::{Crc, CRC_16_MCRF4XX, CRC_32_AUTOSAR};
use crate::engines::IntegrityEngine;

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
