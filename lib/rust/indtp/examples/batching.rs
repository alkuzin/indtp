// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Data aggregation example.

use indtp::{
    Frame, Result,
    engines::{
        CryptographyEngine, IntegrityEngine, SwCryptoEngine, SwIntegrityEngine,
    },
    payload::{Imu3Acc, PayloadType},
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

fn single_sample_mode<I, C>() -> Result<()>
where
    I: IntegrityEngine,
    C: CryptographyEngine,
{
    // -----------------------------------------------------------------------
    // 1) SENDER SIDE: Creating and packing an INDTP frame.
    // -----------------------------------------------------------------------

    // Constructing INDTP frame.
    let mut buffer = [0u8; 64];
    let device_id = 0xFF;
    let payload_type: u8 = PayloadType::Imu6.into();
    let payload_len = size_of::<Imu3Acc>();

    let mut frame =
        Frame::new_lite(&mut buffer, device_id, payload_type, payload_len + 4)?;

    let sample = Imu3Acc {
        acc_x: 1.4.into(),
        acc_y: 2.5.into(),
        acc_z: 3.6.into(),
    };
    let timestamp: u32 = 12345;

    // Enabling single sample mode.
    frame.set_batch(false);
    frame.push_single_sample(timestamp, sample.to_bytes())?;

    let frame_size = frame.pack::<I, C>(None)?;
    println!("Frame size: {} bytes", frame_size);

    let packed_frame = frame.frame_mut()?;
    println!("Hex: {:02X?}\n", packed_frame);
    // Then sending frame ...

    // -----------------------------------------------------------------------
    // 2) RECEIVER SIDE: Validating and parsing INDTP frame.
    // -----------------------------------------------------------------------

    // Frame::parse method do both parsing & validation of received frame.
    let frame = Frame::parse::<I, C>(packed_frame, None)?;
    let header = frame.header();

    let (timestamp, payload_bytes) = frame.read_single_sample()?;
    let payload = Imu3Acc::from_bytes(payload_bytes)?;

    println!("Parsed device ID: {:#02X}", header.device_id);
    println!("Timestamp: {timestamp}");
    println!("Payload length: {} bytes", payload.size());
    println!("Payload (hex): {:02X?}", payload_bytes);
    println!("Payload:\n{:#?}", payload);

    Ok(())
}

fn batching_mode<I, C>() -> Result<()>
where
    I: IntegrityEngine,
    C: CryptographyEngine,
{
    // -----------------------------------------------------------------------
    // 1) SENDER SIDE: Creating and packing an INDTP frame.
    // -----------------------------------------------------------------------

    // Constructing INDTP frame.
    let mut buffer = [0u8; 156];
    let device_id = 0xFF;
    let payload_type: u8 = PayloadType::Imu6.into();
    let payload_len = 128;

    let mut frame =
        Frame::new_lite(&mut buffer, device_id, payload_type, payload_len)?;

    // Enabling data aggregation mode.
    frame.set_batch(true);
    let mut batch = frame.start_batch()?;

    let samples = [
        (
            1_000_000u32,
            Imu3Acc {
                acc_x: 1.0.into(),
                acc_y: 2.0.into(),
                acc_z: 3.0.into(),
            },
        ),
        (
            1_000_100u32,
            Imu3Acc {
                acc_x: 2.0.into(),
                acc_y: 4.0.into(),
                acc_z: 9.0.into(),
            },
        ),
        (
            1_000_150u32,
            Imu3Acc {
                acc_x: 3.0.into(),
                acc_y: 8.0.into(),
                acc_z: 1.0.into(),
            },
        ),
    ];

    for (t, data) in samples.iter() {
        batch.push_sample(*t, &data.to_bytes())?;
    }
    drop(batch);

    let frame_size = frame.pack::<I, C>(None)?;
    println!("Frame size: {} bytes", frame_size);

    let packed_frame = frame.frame_mut()?;
    println!("Hex: {:02X?}\n", packed_frame);
    // Then sending frame ...

    // -----------------------------------------------------------------------
    // 2) RECEIVER SIDE: Validating and parsing INDTP frame.
    // -----------------------------------------------------------------------

    // Frame::parse method do both parsing & validation of received frame.
    let frame = Frame::parse::<I, C>(packed_frame, None)?;
    let iterator = frame.read_batch_samples(size_of::<Imu3Acc>())?;

    println!("Received {} samples:", iterator.len());

    for (i, result) in iterator.enumerate() {
        let (timestamp, data) = result?;
        let sample = Imu3Acc::from_bytes(data)?;
        let (acc_x, acc_y, acc_z) = (sample.acc_x, sample.acc_y, sample.acc_z);

        println!(
            "[{i}] t={timestamp} μs: acc=[{acc_x:.2}, {acc_y:.2}, {acc_z:.2}]",
        );
    }

    Ok(())
}

fn run_example<I, C>() -> Result<()>
where
    I: IntegrityEngine,
    C: CryptographyEngine,
{
    println!("Running single sample mode example:");
    single_sample_mode::<I, C>()?;

    println!("\nRunning batching mode example:");
    batching_mode::<I, C>()?;
    Ok(())
}
