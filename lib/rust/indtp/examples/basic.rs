// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Basic usage example.

use indtp::{
    Frame, Result,
    engines::{
        CryptographyEngine, IntegrityEngine, SwCryptoEngine, SwIntegrityEngine,
    },
    payload::{Imu3Acc, Imu3Gyr, Imu6, PayloadType},
    types::Packable,
};

fn main() {
    // Some methods require integrity checking and/or cryptography engines.
    //
    // If needed default software-based implementations can be easily changed
    // with custom or hardware-assisted implementations.
    if let Err(e) = run_example::<SwIntegrityEngine, SwCryptoEngine>() {
        eprintln!("Error occurred: {e}");
    }
}

fn run_example<I, C>() -> Result<()>
where
    I: IntegrityEngine,
    C: CryptographyEngine,
{
    // -----------------------------------------------------------------------
    // 1) SENDER SIDE: Creating and packing an INDTP frame.
    // -----------------------------------------------------------------------

    // Preparing data to send.
    let payload = Imu6 {
        acc: Imu3Acc {
            acc_x: 1.7,
            acc_y: 2.8,
            acc_z: 3.9,
        },
        gyr: Imu3Gyr {
            gyr_x: 4.0,
            gyr_y: 5.1,
            gyr_z: 6.2,
        },
    };

    // Constructing INDTP frame in Lite mode.
    let mut buffer = [0u8; 38];
    let device_id = 0xFF;
    let payload_type: u8 = PayloadType::Imu6.into();
    let payload_len = payload.size();

    // For all protocol operating modes API is almost the same.
    // Only Frame object construction is a little bit different:
    //
    // let mut frame =
    // Frame::new_lite(&mut buffer, device_id, payload_type, payload_len)?;
    // or:
    // Frame::new_verified(&mut buffer, device_id, payload_type, payload_len)?;
    // or:
    // Frame::new_trusted(&mut buffer, device_id, payload_type, payload_len)?;
    // or:
    // Frame::new_critical(&mut buffer, device_id, payload_type, payload_len)?;
    //
    // For custom frame set up the one should use Frame::new() method:
    //
    // let mut frame = Frame::new(
    //     &mut buffer,
    //     device_id,
    //     payload_type,
    //     payload_len,
    //     Flags::new()
    //         .with_mode(Mode::Verified)
    //         .with_encryption(true)
    //         .with_priority(false)
    //         .with_batch(true)
    //         .build(),
    // );
    let mut frame =
        Frame::new_lite(&mut buffer, device_id, payload_type, payload_len)?;

    // Setting payload & packing frame.
    frame.set_payload(&payload)?;
    let frame_size = frame.pack::<I, C>(None)?;
    println!("Frame size: {} bytes", frame_size);

    let packed_frame = frame.frame()?;
    println!("Hex: {:02X?}\n", packed_frame);
    // Then sending frame ...

    // -----------------------------------------------------------------------
    // 2) RECEIVER SIDE: Validating and parsing INDTP frame.
    // -----------------------------------------------------------------------

    let mut buffer = [0u8; 38];
    buffer.copy_from_slice(packed_frame);

    // Frame::parse method do both parsing & validation of received frame.
    let frame = Frame::parse::<I, C>(&mut buffer, None)?;

    let header = frame.header();
    let payload_bytes = frame.payload()?;
    let payload = Imu6::from_bytes(payload_bytes)?;

    println!("Parsed device ID: {:#02X}", header.device_id);
    println!("Payload length: {} bytes", payload.size());
    println!("Payload (hex): {:02X?}", payload_bytes);
    println!("Payload:\n{:#?}", payload);

    Ok(())
}
