// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP frame standard payload types.

#![allow(unused)]
use crate::prelude::*;

indtp_data! {
    /// Accelerometer only (for 3-axis sensor).
    #[derive(Default)]
    pub struct Imu3Acc {
        /// Acceleration along the X-axis in
        /// meters per second squared (`m/s²`).
        pub acc_x: F32,
        /// Acceleration along the Y-axis in
        /// meters per second squared (`m/s²`).
        pub acc_y: F32,
        /// Acceleration along the Z-axis in
        /// meters per second squared (`m/s²`).
        pub acc_z: F32,
    }

    /// Gyroscope only (for 3-axis sensor).
    #[derive(Default)]
    pub struct Imu3Gyr {
        /// Angular velocity along the X-axis in
        /// radians per second (`rad/s`).
        pub gyr_x: F32,
        /// Angular velocity along the Y-axis in
        /// radians per second (`rad/s`).
        pub gyr_y: F32,
        /// Angular velocity along the Z-axis in
        /// radians per second (`rad/s`).
        pub gyr_z: F32,
    }

    /// Magnetometer only (for 3-axis sensor).
    #[derive(Default)]
    pub struct Imu3Mag {
        /// Magnetic field induction along the X-axis in
        /// microteslas (`μT`).
        pub mag_x: F32,
        /// Magnetic field induction along the Y-axis in
        /// microteslas (`μT`).
        pub mag_y: F32,
        /// Magnetic field induction along the Z-axis in
        /// microteslas (`μT`).
        pub mag_z: F32,
    }

    /// Accelerometer + Gyroscope readings (for 6-axis sensor).
    #[derive(Default)]
    pub struct Imu6 {
        /// Accelerometer readings along 3 axes.
        pub acc: Imu3Acc,
        /// Gyroscope readings along 3 axes.
        pub gyr: Imu3Gyr,
    }

    /// Accelerometer + Gyroscope + Magnetometer readings
    /// (for 9-axis sensor).
    #[derive(Default)]
    pub struct Imu9 {
        /// Accelerometer readings along 3 axes.
        pub acc: Imu3Acc,
        /// Gyroscope readings along 3 axes.
        pub gyr: Imu3Gyr,
        /// Magnetometer readings along 3 axes.
        pub mag: Imu3Mag,
    }

    /// Accelerometer + Gyroscope + Magnetometer + Barometer readings
    /// (for 10-axis sensor).
    #[derive(Default)]
    pub struct Imu10 {
        /// Accelerometer readings along 3 axes.
        pub acc: Imu3Acc,
        /// Gyroscope readings along 3 axes.
        pub gyr: Imu3Gyr,
        /// Magnetometer readings along 3 axes.
        pub mag: Imu3Mag,
        /// Atmospheric pressure in Pascals (`Pa`).
        pub baro: F32,
    }

    /// Attitude. Hamiltonian Quaternion (w, x, y, z).
    /// **MUST** be normalized.
    #[derive(Default)]
    pub struct ImuQuat {
        /// Scalar component.
        pub w: F32,
        /// Vector X component.
        pub x: F32,
        /// Vector Y component.
        pub y: F32,
        /// Vector Z component.
        pub z: F32,
    }
}

impl Packable for Imu3Acc {}

impl Payload for Imu3Acc {
    const TYPE_ID: u8 = PayloadType::Imu3Acc.as_u8();
}

impl Packable for Imu3Gyr {}

impl Payload for Imu3Gyr {
    const TYPE_ID: u8 = PayloadType::Imu3Gyr.as_u8();
}

impl Packable for Imu3Mag {}

impl Payload for Imu3Mag {
    const TYPE_ID: u8 = PayloadType::Imu3Mag.as_u8();
}

impl Packable for Imu6 {}

impl Payload for Imu6 {
    const TYPE_ID: u8 = PayloadType::Imu6.as_u8();
}

impl Packable for Imu9 {}

impl Payload for Imu9 {
    const TYPE_ID: u8 = PayloadType::Imu9.as_u8();
}

impl Packable for Imu10 {}

impl Payload for Imu10 {
    const TYPE_ID: u8 = PayloadType::Imu10.as_u8();
}

impl Packable for ImuQuat {}

impl Payload for ImuQuat {
    const TYPE_ID: u8 = PayloadType::ImuQuat.as_u8();
}
