// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP frame payload related declarations.

#[cfg(feature = "std_payloads")]
mod std;

use core::ops::Range;
#[cfg(feature = "std_payloads")]
#[allow(unused)]
pub use std::*;
use crate::payload::PayloadType::Reserved;
use crate::prelude::*;

/// Standard payload type range.
pub const STANDARD_PAYLOAD_RANGE: Range<u8> = 0x00..0x7F + 1;

#[allow(unused)]
/// Vendor-specific payload type range.
pub const VENDOR_PAYLOAD_RANGE: Range<u8> = 0x80..0xFF;

/// Trait that **RECOMMENDED** to be used for INDTP payload.
pub trait Payload: Sized + Packable {
    /// Payload type identifier according to INDTP specification.
    const TYPE_ID: u8;

    /// Get payload type.
    ///
    /// # Returns
    /// - Payload type according to INDTP specification.
    #[inline]
    #[must_use]
    fn payload_type() -> u8 {
        Self::TYPE_ID
    }

    /// Get payload length.
    ///
    /// # Returns
    /// - Payload length in bytes.
    #[inline]
    #[must_use]
    fn len() -> usize {
        size_of::<Self>()
    }
}

/// Enumeration of standard payload types.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum PayloadType {
    /// Accelerometer only (for 3-axis sensor).
    Imu3Acc = 0x00,
    /// Gyroscope only (for 3-axis sensor).
    Imu3Gyr = 0x01,
    /// Magnetometer only (for 3-axis sensor).
    Imu3Mag = 0x02,
    /// Accelerometer + Gyroscope readings (for 6-axis sensor).
    Imu6 = 0x03,
    /// Accelerometer + Gyroscope + Magnetometer readings
    /// (for 9-axis sensor).
    Imu9 = 0x04,
    /// Accelerometer + Gyroscope + Magnetometer + Barometer readings
    /// (for 10-axis sensor).
    Imu10 = 0x05,
    /// Attitude. Hamiltonian Quaternion (w, x, y, z).
    /// **MUST** be normalized.
    ImuQuat = 0x06,
    /// Other reserved types.
    Reserved(u8),
}

impl PayloadType {
    /// Check whether payload type is standard or not.
    ///
    /// # Returns
    /// - `true` - if payload type is standard.
    /// - `false` - if payload type is vendor-specific.
    #[inline]
    pub fn is_standard(&self) -> bool {
        let t = u8::from(*self);
        STANDARD_PAYLOAD_RANGE.contains(&(t))
    }

    /// Check whether payload type is vendor-specific or not.
    ///
    /// # Returns
    /// - `true` - if payload type is vendor-specific.
    /// - `false` - if payload type is standard.
    #[inline]
    pub fn is_vendor(&self) -> bool {
        let t = u8::from(*self);
        VENDOR_PAYLOAD_RANGE.contains(&(t))
    }

    /// Convert payload type to u8.
    ///
    /// # Returns
    /// - Payload type in byte representation.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        match self {
            PayloadType::Imu3Acc => 0x00,
            PayloadType::Imu3Gyr => 0x01,
            PayloadType::Imu3Mag => 0x02,
            PayloadType::Imu6 => 0x03,
            PayloadType::Imu9 => 0x04,
            PayloadType::Imu10 => 0x05,
            PayloadType::ImuQuat => 0x06,
            Reserved(value) => value,
        }
    }
}

impl From<PayloadType> for u8 {
    fn from(payload_type: PayloadType) -> u8 {
        payload_type.as_u8()
    }
}

impl From<u8> for PayloadType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Imu3Acc,
            0x01 => Self::Imu3Gyr,
            0x02 => Self::Imu3Mag,
            0x03 => Self::Imu6,
            0x04 => Self::Imu9,
            0x05 => Self::Imu10,
            0x06 => Self::ImuQuat,
            _ => Reserved(value),
        }
    }
}
