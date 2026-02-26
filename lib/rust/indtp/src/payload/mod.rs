// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP frame payload related declarations.

#[cfg(feature = "std_payloads")]
mod std;

use core::ops::Range;
#[cfg(feature = "std_payloads")]
pub use std::*;

use crate::prelude::*;

/// Standard payload type range.
pub const STANDARD_PAYLOAD_RANGE: Range<u8> = 0x00..0x7F + 1;

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
}

/// Trait for converting payload to metrics array and vice versa.
pub trait AsMetricsArray<const N: usize> {
    /// Convert metrics to a fixed-size array for.
    ///
    /// # Returns
    /// - Fixed-size array of payload members.
    fn to_array(&self) -> [f32; N];
}

/// Enumeration of standard payload types.
#[derive(Debug)]
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
}

impl From<PayloadType> for u8 {
    /// Convert payload type enumeration to u8.
    ///
    /// # Parameters
    /// - `mode` - given payload type to convert.
    ///
    /// # Returns
    /// -  Payload type enumeration member in u8 representation.
    fn from(payload_type: PayloadType) -> Self {
        payload_type as Self
    }
}

impl TryFrom<u8> for PayloadType {
    /// The type returned in the event of a conversion error.
    type Error = Error;

    /// Try to convert byte to INDTP standard payload type.
    ///
    /// # Parameters
    /// - `byte` - given byte to convert.
    ///
    /// # Returns
    /// - INDTP standard payload type from byte - in case of success.
    /// - Error otherwise.
    ///
    /// # Errors
    /// - Parse Error.
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Imu3Acc),
            0x01 => Ok(Self::Imu3Gyr),
            0x02 => Ok(Self::Imu3Mag),
            0x03 => Ok(Self::Imu6),
            0x04 => Ok(Self::Imu9),
            0x05 => Ok(Self::Imu10),
            0x06 => Ok(Self::ImuQuat),
            _ => Err(Error::ParseError),
        }
    }
}
