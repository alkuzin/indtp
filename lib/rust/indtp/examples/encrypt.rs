// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Payload encryption example.

use indtp::{
    Frame, Result,
    engines::{
        CryptographyEngine, IntegrityEngine, SwCryptoEngine, SwIntegrityEngine,
    },
    payload::{Imu6, Imu3Acc, Imu3Gyr, PayloadType},
    types::{Packable, AesKey, CryptoKeys, HmacKey},
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

    // Constructing INDTP frame.
    let mut buffer = [0u8; 70];
    let device_id = 0xFF;
    let payload_type: u8 = PayloadType::Imu6.into();
    let payload_len = payload.size();

    let mut frame =
        Frame::new_critical(&mut buffer, device_id, payload_type, payload_len)?;

    // Encrypting payload & packing frame.
    frame.set_payload(&payload)?;

    let aes_key: AesKey = [0x42_u8; 16];
    let hmac_key: HmacKey = [0x21_u8; 32];
    let keys = CryptoKeys::new(aes_key, hmac_key);

    // Encryption flag must be set before encryption.
    frame.set_encrypted(true);
    frame.encrypt::<C>(&keys)?;

    let frame_size = frame.pack::<I, C>(Some(&keys))?;
    println!("Frame size: {} bytes", frame_size);

    let packed_frame = frame.frame()?;
    println!("Hex: {:02X?}\n", packed_frame);
    // Then sending frame ...

    // -----------------------------------------------------------------------
    // 2) RECEIVER SIDE: Validating and parsing INDTP frame.
    // -----------------------------------------------------------------------

    let mut buffer = [0u8; 70];
    buffer.copy_from_slice(packed_frame);

    // Frame::parse method do both parsing & validation of received frame.
    let mut frame = Frame::parse::<I, C>(&mut buffer, Some(&keys))?;

    if frame.is_encrypted() {
        frame.decrypt::<C>(&keys)?;
    }

    let header = frame.header();
    let payload_bytes = frame.payload()?;
    let payload = Imu6::from_bytes(payload_bytes)?;

    println!("Parsed device ID: {:#02X}", header.device_id);
    println!("Payload length: {} bytes", payload.size());
    println!("Payload (hex): {:02X?}", payload_bytes);
    println!("Payload:\n{:#?}", payload);

    Ok(())
}
