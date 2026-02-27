// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP frame related declarations.

use crate::prelude::*;
use zerocopy::little_endian::{U16, U32};

/// Maximum Transmission Unit (MTU) size in bytes.
///
/// The total INDTP frame size (header + payload + trailer) **MUST NOT** exceed
/// 1024 bytes. This size was chosen in order to fit well within the common
/// Ethernet MTU (1500 bytes) avoiding link‑level fragmentation that can lead
/// to increased latency.
pub const MTU_SIZE: usize = 1024;

/// Max size of frame trailer in bytes.
pub const MAX_TRAILER_SIZE: usize = 32;

/// Frame payload max size in bytes.
pub const PAYLOAD_MAX_SIZE: usize = MTU_SIZE - HEADER_SIZE - MAX_TRAILER_SIZE;

/// Frame - is a data exchange unit of INDTP.
/// Every frame consists of three distinct sections: a fixed-size header,
/// a variable-size payload, and a mode-dependent trailer.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Frame buffer.
    buffer: &'a mut [u8],
    /// Payload length in bytes.
    payload_len: usize,
    /// Frame trailer length in bytes.
    trailer_len: usize,
}

impl<'a> Frame<'a> {
    /// Construct new INDTP frame in `Lite` operating mode.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to handle.
    /// - `device_id` - given unique identifier of the source navigation node.
    /// - `payload_type` - given type of frame payload.
    /// - `payload_len` - given payload length in bytes.
    ///
    /// # Returns
    /// - New INDTP frame - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Buffer overflow.
    /// - Parse errors.
    #[allow(unused)]
    #[inline]
    pub fn new_lite(
        buffer: &'a mut [u8],
        device_id: u8,
        payload_type: u8,
        payload_len: usize,
    ) -> Result<Self> {
        let flags = Flags::new().with_mode(Mode::Lite).build();
        Self::new(buffer, device_id, payload_type, payload_len, flags)
    }

    /// Construct new INDTP frame in `Verified` operating mode.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to handle.
    /// - `device_id` - given unique identifier of the source navigation node.
    /// - `payload_type` - given type of frame payload.
    /// - `payload_len` - given payload length in bytes.
    ///
    /// # Returns
    /// - New INDTP frame - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Buffer overflow.
    /// - Parse errors.
    #[allow(unused)]
    #[inline]
    pub fn new_verified(
        buffer: &'a mut [u8],
        device_id: u8,
        payload_type: u8,
        payload_len: usize,
    ) -> Result<Self> {
        let flags = Flags::new().with_mode(Mode::Verified).build();
        Self::new(buffer, device_id, payload_type, payload_len, flags)
    }

    /// Construct new INDTP frame in `Trusted` operating mode.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to handle.
    /// - `device_id` - given unique identifier of the source navigation node.
    /// - `payload_type` - given type of frame payload.
    /// - `payload_len` - given payload length in bytes.
    ///
    /// # Returns
    /// - New INDTP frame - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Buffer overflow.
    /// - Parse errors.
    #[allow(unused)]
    #[inline]
    pub fn new_trusted(
        buffer: &'a mut [u8],
        device_id: u8,
        payload_type: u8,
        payload_len: usize,
    ) -> Result<Self> {
        let flags = Flags::new().with_mode(Mode::Trusted).build();
        Self::new(buffer, device_id, payload_type, payload_len, flags)
    }

    /// Construct new INDTP frame in `Critical` operating mode.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to handle.
    /// - `device_id` - given unique identifier of the source navigation node.
    /// - `payload_type` - given type of frame payload.
    /// - `payload_len` - given payload length in bytes.
    ///
    /// # Returns
    /// - New INDTP frame - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Buffer overflow.
    /// - Parse errors.
    #[allow(unused)]
    #[inline]
    pub fn new_critical(
        buffer: &'a mut [u8],
        device_id: u8,
        payload_type: u8,
        payload_len: usize,
    ) -> Result<Self> {
        let flags = Flags::new().with_mode(Mode::Critical).build();
        Self::new(buffer, device_id, payload_type, payload_len, flags)
    }

    /// Construct new INDTP frame.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to handle.
    /// - `device_id` - given unique identifier of the source navigation node.
    /// - `payload_type` - given type of frame payload.
    /// - `payload_len` - given payload length in bytes.
    /// - `flags` - given protocol flags to handle.
    ///
    /// # Returns
    /// - New INDTP frame - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer underflow.
    /// - Buffer overflow.
    /// - Parse errors.
    pub fn new(
        buffer: &'a mut [u8],
        device_id: u8,
        payload_type: u8,
        payload_len: usize,
        flags: Flags,
    ) -> Result<Self> {
        if payload_len > PAYLOAD_MAX_SIZE {
            return Err(Error::BufferOverflow);
        }

        let mode = Mode::try_from(flags).map_err(|_| Error::ParseError)?;
        let trailer_len = Self::trailer_len_from_mode(mode);
        let total_len = HEADER_SIZE + payload_len + trailer_len;

        if buffer.len() < total_len {
            return Err(Error::BufferUnderflow);
        }

        let header_ptr = buffer.as_mut_ptr() as *mut Header;
        let header = unsafe { &mut *header_ptr };

        header.preamble = U32::new(Header::PREAMBLE);
        header.version = INDTP_VERSION;
        header.flags = flags.bits();
        header.device_id = device_id;
        header.payload_type = payload_type;
        header.sequence = U16::new(0);
        header.payload_len = U16::new(payload_len as u16);

        Ok(Self {
            buffer,
            payload_len,
            trailer_len: Self::trailer_len_from_mode(mode),
        })
    }

    /// Get frame header reference.
    ///
    /// # Returns
    /// - Reference to frame header slice.
    #[inline]
    pub fn header(&self) -> &Header {
        let ptr = self.buffer.as_ptr() as *const Header;
        unsafe { &*ptr }
    }

    /// Get mutable frame header reference.
    ///
    /// # Returns
    /// - Mutable reference to frame header slice.
    #[inline]
    pub fn header_mut(&mut self) -> &mut Header {
        let ptr = self.buffer.as_mut_ptr() as *mut Header;
        unsafe { &mut *ptr }
    }

    /// Get protocol flags.
    ///
    /// # Returns
    /// - Protocol flags type-safe wrapper.
    #[inline]
    pub fn flags(&self) -> Flags {
        Flags::from_bits_truncate(self.header().flags)
    }

    /// Set flags from a type-safe bitflags struct.
    /// Set protocol flags.
    ///
    /// # Parameters
    /// - `flags` - given protocol flags type-safe wrapper to handle.
    #[inline]
    pub fn set_flags(&mut self, flags: Flags) {
        self.header_mut().flags = flags.bits();
    }

    /// Set protocol operating mode.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to set.
    #[inline]
    pub fn set_mode(&mut self, mode: Mode) {
        let mut flags = self.flags();
        flags.remove(Flags::MODE_MASK);
        flags.insert(mode.into());
        self.header_mut().flags = flags.bits();
    }

    /// Get protocol operating mode.
    ///
    /// # Returns
    /// - Protocol operating mode - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse error.
    #[inline]
    pub fn mode(&self) -> Result<Mode> {
        let flags = self.flags();
        Mode::try_from(flags)
    }

    /// Check whether data aggregation is enabled or not for payload.
    ///
    /// # Returns
    /// - `true` - if batch mode is enabled.
    /// - `false` - if single sample mode is enabled.
    #[inline]
    pub fn is_batch(&self) -> bool {
        let flags = self.flags();
        flags.contains(Flags::BATCH)
    }

    /// Enable/disable data aggregation for payload.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    #[inline]
    pub fn set_batch(&mut self, enabled: bool) {
        let mut flags = self.flags();
        flags.set(Flags::BATCH, enabled);
        self.header_mut().flags = flags.bits();
    }

    /// Check whether payload is encrypted or not.
    ///
    /// # Returns
    /// - `true` - if payload is encrypted.
    /// - `false` - if payload is plaintext.
    #[inline]
    pub fn is_encrypted(&self) -> bool {
        let flags = self.flags();
        flags.contains(Flags::ENCRYPT)
    }

    /// Set/unset payload encryption flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    #[inline]
    pub fn set_encrypted(&mut self, enabled: bool) {
        let mut flags = self.flags();
        flags.set(Flags::ENCRYPT, enabled);
        self.header_mut().flags = flags.bits();
    }

    /// Check whether frame handling has high priority.
    ///
    /// # Returns
    /// - `true` - if frame handling has high priority.
    /// - `false` - if frame handling has low priority.
    #[inline]
    pub fn is_high_priority(&self) -> bool {
        let flags = self.flags();
        flags.contains(Flags::PRIORITY)
    }

    /// Set frame handling priority.
    ///
    /// # Parameters
    /// - `high` - given flag to handle.
    #[inline]
    pub fn set_priority(&mut self, high: bool) {
        let mut flags = self.flags();
        flags.set(Flags::PRIORITY, high);
        self.header_mut().flags = flags.bits();
    }

    /// Get payload reference.
    ///
    /// # Returns
    /// - Reference to payload byte slice.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn payload(&self) -> Result<&[u8]> {
        let begin = HEADER_SIZE;
        let data = self
            .buffer
            .get(begin..begin + self.payload_len)
            .ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Get mutable payload reference.
    ///
    /// # Returns
    /// - Mutable reference to payload byte slice.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn payload_mut(&mut self) -> Result<&mut [u8]> {
        let begin = HEADER_SIZE;
        let data = self
            .buffer
            .get_mut(begin..begin + self.payload_len)
            .ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Get frame trailer reference.
    ///
    /// # Returns
    /// - Reference to frame trailer byte slice.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn trailer(&self) -> Result<&[u8]> {
        let begin = HEADER_SIZE + self.payload_len;
        let data = self
            .buffer
            .get(begin..begin + self.trailer_len)
            .ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Get mutable frame trailer reference.
    ///
    /// # Returns
    /// - Mutable reference to frame trailer byte slice - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn trailer_mut(&mut self) -> Result<&mut [u8]> {
        let begin = HEADER_SIZE + self.payload_len;
        let data = self
            .buffer
            .get_mut(begin..begin + self.trailer_len)
            .ok_or(Error::ParseError)?;

        Ok(data)
    }

    /// Get frame payload length.
    ///
    /// # Returns
    /// - Payload length in bytes.
    #[allow(unused)]
    #[inline]
    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Get frame trailer length.
    ///
    /// # Returns
    /// - Trailer length in bytes.
    #[allow(unused)]
    #[inline]
    fn trailer_len(&self) -> usize {
        self.trailer_len
    }

    /// Get frame trailer length from mode.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to handle.
    ///
    /// # Returns
    /// - Trailer length in bytes.
    #[must_use]
    fn trailer_len_from_mode(mode: Mode) -> usize {
        match mode {
            Mode::Lite => 0,
            Mode::Verified => 4,
            Mode::Trusted => 8,
            Mode::Critical => 32,
        }
    }

    /// Set frame payload from raw bytes.
    ///
    /// # Parameters
    /// - `bytes` - given payload bytes to set.
    /// - `payload_type` - given payload type to set.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer overflow.
    pub fn set_payload_raw(
        &mut self,
        bytes: &[u8],
        payload_type: u8,
    ) -> Result<()> {
        let payload_len = bytes.len();

        if payload_len > PAYLOAD_MAX_SIZE {
            return Err(Error::BufferOverflow);
        }

        self.payload_mut()?.copy_from_slice(bytes);

        #[allow(clippy::cast_possible_truncation)]
        {
            self.header_mut().payload_type = payload_type;
            self.header_mut().payload_len = U16::new(payload_len as u16);
            self.payload_len = payload_len;
        }

        Ok(())
    }

    /// Set frame payload.
    ///
    /// # Parameters
    /// - `payload` - given payload data to set.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Buffer overflow.
    pub fn set_payload<T: Payload>(&mut self, payload: &T) -> Result<()> {
        let payload_len = payload.size();

        if payload_len > PAYLOAD_MAX_SIZE {
            return Err(Error::BufferOverflow);
        }

        self.payload_mut()?.copy_from_slice(payload.to_bytes());
        #[allow(clippy::cast_possible_truncation)]
        {
            self.header_mut().payload_type = T::payload_type();
            self.header_mut().payload_len = U16::new(payload_len as u16);
            self.payload_len = payload_len;
        }

        Ok(())
    }

    /// Get part of the frame containing the header and payload.
    ///
    /// # Returns
    /// - Byte slice of the frame containing the header and payload.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn authenticated_data(&self) -> Result<&[u8]> {
        let end = HEADER_SIZE + self.payload_len;
        let data = self.buffer.get(0..end).ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Write frame trailer.
    ///
    /// # Parameters
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Missing keys.
    /// - Cryptographic errors.
    fn write_trailer<I, C>(&mut self, keys: Option<&CryptoKeys>) -> Result<()>
    where
        I: IntegrityEngine,
        C: CryptographyEngine,
    {
        let auth_data = self.authenticated_data()?;
        let mode = self.mode()?;

        match mode {
            Mode::Lite => {}
            Mode::Verified => {
                let crc32 = I::compute_crc32(auth_data);
                self.trailer_mut()?.copy_from_slice(&crc32.to_le_bytes());
            }
            Mode::Trusted => {
                let k = keys.ok_or(Error::MissingKeys)?;
                let mut mac = [0u8; 8];
                C::compute_cmac(&k.aes_key, auth_data, &mut mac)?;
                self.trailer_mut()?.copy_from_slice(&mac);
            }
            Mode::Critical => {
                let k = keys.ok_or(Error::MissingKeys)?;
                let mut mac = [0u8; 32];
                C::compute_hmac(&k.hmac_key, auth_data, &mut mac)?;
                self.trailer_mut()?.copy_from_slice(&mac);
            }
        }

        Ok(())
    }

    /// Validate frame trailer.
    ///
    /// # Parameters
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Missing keys.
    /// - Cryptographic errors.
    /// - Parse errors.
    /// - Incorrect CRC.
    /// - Failed authorisation.
    fn validate_trailer<I, C>(&self, keys: Option<&CryptoKeys>) -> Result<()>
    where
        I: IntegrityEngine,
        C: CryptographyEngine,
    {
        let auth_data = self.authenticated_data()?;
        let trailer_bytes = self.trailer()?;
        let mode = self.mode()?;

        match mode {
            Mode::Lite => {}
            Mode::Verified => {
                let trailer: [u8; 4] = trailer_bytes
                    .get(0..4)
                    .ok_or(Error::ParseError)?
                    .try_into()
                    .map_err(|_| Error::ParseError)?;

                let received_crc = U32::from(trailer);
                let computed_crc = I::compute_crc32(auth_data);

                if received_crc != computed_crc {
                    return Err(Error::IncorrectCrc);
                }
            }
            Mode::Trusted => {
                let k = keys.ok_or(Error::MissingKeys)?;
                let received_mac = trailer_bytes;
                let mut computed_mac = [0u8; 8];

                C::compute_cmac(&k.aes_key, auth_data, &mut computed_mac)?;

                if received_mac != computed_mac {
                    return Err(Error::AuthFailed);
                }
            }
            Mode::Critical => {
                let k = keys.ok_or(Error::MissingKeys)?;
                let received_mac = trailer_bytes;
                let mut computed_mac = [0u8; 32];

                C::compute_hmac(&k.hmac_key, auth_data, &mut computed_mac)?;

                if received_mac != computed_mac {
                    return Err(Error::AuthFailed);
                }
            }
        }

        Ok(())
    }

    /// Parse frame from raw bytes.
    ///
    /// # Parameters
    /// - `buffer` - given buffer to parse frame from.
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Missing keys.
    /// - Cryptographic errors.
    /// - Parse errors.
    /// - Incorrect CRC.
    /// - Failed authorisation.
    pub fn parse<I, C>(
        buffer: &'a mut [u8],
        keys: Option<&CryptoKeys>,
    ) -> Result<Self>
    where
        I: IntegrityEngine,
        C: CryptographyEngine,
    {
        match Header::validate::<I>(buffer) {
            Ok(_) => {
                let header = Header::from_bytes(buffer)
                    .map_err(|_| Error::ParseError)?;

                let frame = Self::new(
                    buffer,
                    header.device_id,
                    header.payload_type,
                    header.payload_len.into(),
                    Flags::from_bits(header.flags).ok_or(Error::ParseError)?,
                )
                .map_err(|_| Error::ParseError)?;

                frame.validate_trailer::<I, C>(keys)?;
                Ok(frame)
            }
            Err(e) => Err(e),
        }
    }

    /// Pack frame to raw bytes.
    ///
    /// # Parameters
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - Total size of the frame in bytes - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Missing keys.
    /// - Cryptographic errors.
    /// - Parse errors.
    /// - Incorrect CRC.
    /// - Failed authorisation.
    #[inline]
    pub fn pack<I, C>(&mut self, keys: Option<&CryptoKeys>) -> Result<usize>
    where
        I: IntegrityEngine,
        C: CryptographyEngine,
    {
        let crc = self.header().compute_crc::<I>()?;
        self.header_mut().crc = U16::from(crc);
        self.write_trailer::<I, C>(keys)?;

        Ok(self.size())
    }

    /// Get total size of the frame.
    ///
    /// # Returns
    /// - Total size of the frame in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        HEADER_SIZE + self.payload_len + self.trailer_len
    }

    /// Get frame reference.
    ///
    /// # Returns
    /// - Reference to frame byte slice.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn frame(&self) -> Result<&[u8]> {
        let data = self.buffer.get(..self.size()).ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Get mutable frame reference.
    ///
    /// # Returns
    /// - Mutable reference to frame byte slice.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    #[inline]
    pub fn frame_mut(&mut self) -> Result<&mut [u8]> {
        let data = self
            .buffer
            .get_mut(..self.size())
            .ok_or(Error::ParseError)?;
        Ok(data)
    }

    /// Start data aggregation.
    ///
    /// # Returns
    /// - Active batch record context - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Invalid operation.
    /// - Buffer overflow.
    /// - Parse errors.
    pub fn start_batch(&mut self) -> Result<Batch<'_, 'a>> {
        if self.is_batch() {
            if self.payload_len < 1 {
                return Err(Error::BufferOverflow);
            }

            if let Some(first_byte) = self.payload_mut()?.get_mut(0) {
                *first_byte = 0;
            }

            let batch = Batch::new(self);
            return Ok(batch);
        }

        Err(Error::InvalidOperation)
    }

    /// Get an iterator over batched samples.
    ///
    /// # Parameters
    /// - `sample_size` - given size of sensor data portion per sample in bytes.
    ///
    /// # Returns
    /// - An iterator over batched samples - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Invalid operation.
    /// - Parse errors.
    #[inline]
    pub fn read_batch_samples(
        &self,
        sample_size: usize,
    ) -> Result<BatchIterator<'_>> {
        if !self.is_batch() {
            return Err(Error::InvalidOperation);
        }

        BatchIterator::new(self.payload()?, sample_size)
    }

    /// Push single sample. Must be used only if single sample mode is enabled.
    ///
    /// # Parameters
    /// - `timestamp` - given sensor-local time to push.
    /// - `data` - given sample data to store.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Invalid operation.
    /// - Buffer overflow.
    /// - Parse errors.
    pub fn push_single_sample(
        &mut self,
        timestamp: u32,
        data: &[u8],
    ) -> Result<()> {
        if self.is_batch() {
            return Err(Error::InvalidOperation);
        }

        let required_len = 4 + data.len();

        if required_len > self.payload_len() {
            return Err(Error::BufferOverflow);
        }

        let payload = self.payload_mut()?;

        payload
            .get_mut(0..4)
            .ok_or(Error::ParseError)?
            .copy_from_slice(&timestamp.to_le_bytes());

        payload
            .get_mut(4..required_len)
            .ok_or(Error::ParseError)?
            .copy_from_slice(data);

        Ok(())
    }

    /// Read single sample. Must be used only if single sample mode is enabled.
    ///
    /// # Returns
    /// - Sensor-local time & sample data - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Invalid operation.
    /// - Buffer overflow.
    /// - Parse errors.
    pub fn read_single_sample(&self) -> Result<(u32, &[u8])> {
        if self.is_batch() {
            return Err(Error::InvalidOperation);
        }

        let payload = self.payload()?;

        let timestamp_bytes = payload
            .get(0..4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(Error::ParseError)?;

        let timestamp = u32::from_le_bytes(timestamp_bytes);
        let data = payload.get(4..).ok_or(Error::ParseError)?;

        Ok((timestamp, data))
    }

    /// Encrypt payload. Only if `ENCRYPT` flag is set.
    ///
    /// # Parameters
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Cryptographic errors.
    /// - Parse errors.
    /// - Invalid operation.
    pub fn encrypt<C>(&mut self, keys: &CryptoKeys) -> Result<()>
    where
        C: CryptographyEngine,
    {
        if !self.is_encrypted() {
            return Err(Error::InvalidOperation);
        }

        let header = self.header();
        let sequence_bytes = header.sequence.to_bytes();

        // Nonce structure:
        // nonce = [device ID (1 byte)] | [sequence number (2 bytes)] |
        // [padding (zeros) up to 16 bytes]
        let mut nonce = [0u8; 16];
        nonce[0] = header.device_id;
        nonce[1] = sequence_bytes[0];
        nonce[2] = sequence_bytes[1];

        C::compute_aes_ctr(&keys.aes_key, &nonce, self.payload_mut()?)?;
        Ok(())
    }

    /// Decrypt payload. Only if `ENCRYPT` flag is set.
    ///
    /// # Parameters
    /// - `keys` - given cryptographic keys to handle.
    ///
    /// # Returns
    /// - `Ok` - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Cryptographic errors.
    /// - Parse errors.
    /// - Invalid operation.
    #[inline]
    pub fn decrypt<C>(&mut self, keys: &CryptoKeys) -> Result<()>
    where
        C: CryptographyEngine,
    {
        self.encrypt::<C>(keys)?;
        self.set_encrypted(false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_creation() {
        let mut buffer = [0_u8; 128];
        let _ = Frame::new(
            &mut buffer,
            0xAB,
            0x00,
            0x06,
            Flags::new()
                .with_mode(Mode::Lite)
                .with_batch(true)
                .with_encryption(true)
                .with_priority(false)
                .build(),
        )
        .unwrap();
    }

    #[test]
    fn test_frame_creation_failed() {
        let mut buffer = [0_u8; 3];
        let frame = Frame::new_lite(&mut buffer, 0xAB, 0x00, 0x06);
        assert!(frame.is_err());
    }

    /// Auxiliary function for creating INDTP frame for tests.
    fn create_test_frame(buffer: &'_ mut [u8]) -> Frame<'_> {
        Frame::new_lite(buffer, 0xAB, 0x00, 0x06).unwrap()
    }

    #[test]
    fn test_indtp_set_and_get_mode() {
        let mut buffer = [0_u8; 128];
        let mut frame = create_test_frame(&mut buffer);

        let mode = Mode::Lite;
        frame.set_mode(mode);
        assert_eq!(mode, frame.mode().unwrap());

        let mode = Mode::Verified;
        frame.set_mode(mode);
        assert_eq!(mode, frame.mode().unwrap());

        let mode = Mode::Trusted;
        frame.set_mode(mode);
        assert_eq!(mode, frame.mode().unwrap());

        let mode = Mode::Critical;
        frame.set_mode(mode);
        assert_eq!(mode, frame.mode().unwrap());
    }

    #[test]
    fn test_indtp_set_and_get_batch() {
        let mut buffer = [0_u8; 128];
        let mut frame = create_test_frame(&mut buffer);

        let state = true;
        frame.set_batch(state);
        assert_eq!(state, frame.is_batch());

        let state = false;
        frame.set_batch(state);
        assert_eq!(state, frame.is_batch());
    }

    #[test]
    fn test_indtp_set_and_get_encrypted() {
        let mut buffer = [0_u8; 128];
        let mut frame = create_test_frame(&mut buffer);

        let state = true;
        frame.set_encrypted(state);
        assert_eq!(state, frame.is_encrypted());

        let state = false;
        frame.set_encrypted(state);
        assert_eq!(state, frame.is_encrypted());
    }

    #[test]
    fn test_indtp_set_and_get_priority() {
        let mut buffer = [0_u8; 128];
        let mut frame = create_test_frame(&mut buffer);

        let state = true;
        frame.set_priority(state);
        assert_eq!(state, frame.is_high_priority());

        let state = false;
        frame.set_priority(state);
        assert_eq!(state, frame.is_high_priority());
    }

    fn create_valid_frame_buffer(
        buffer: &mut [u8],
        mode: Mode,
        payload: &[u8],
    ) {
        let flags = Flags::new().with_mode(mode).build();

        let mut frame = Frame::new(buffer, 0xAB, 0x00, payload.len(), flags)
            .expect("Failed to create frame skeleton");

        frame
            .set_payload_raw(payload, 0x7F)
            .expect("Failed to set payload");

        let keys = CryptoKeys::new([0x42; 16], [0x55; 32]);

        frame
            .pack::<SwIntegrityEngine, SwCryptoEngine>(Some(&keys))
            .expect("Failed to pack frame");
    }

    #[test]
    fn test_parse_success_lite_mode() {
        let payload_data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut buffer = [0_u8; 128];
        create_valid_frame_buffer(&mut buffer, Mode::Lite, &payload_data);

        let frame = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            None,
        )
        .expect("Parsing valid frame failed");

        assert_eq!(frame.mode().unwrap(), Mode::Lite);
        assert_eq!(frame.payload().unwrap(), &payload_data);
        assert_eq!(frame.payload_len(), 4);
        assert_eq!(frame.trailer_len(), 0);
    }

    #[test]
    fn test_parse_invalid_header_crc() {
        let payload_data = [0x01, 0x02];
        let mut buffer = [0_u8; 128];
        create_valid_frame_buffer(&mut buffer, Mode::Lite, &payload_data);

        buffer[6] ^= 0xFF;
        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            None,
        );

        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::IncorrectCrc);
    }

    #[test]
    fn test_parse_invalid_trailer_mac() {
        let payload_data = [0xAA, 0xBB, 0xCC];
        let mut buffer = [0_u8; 128];

        // Checking Verified mode.
        create_valid_frame_buffer(&mut buffer, Mode::Verified, &payload_data);
        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            None,
        );
        assert!(res.is_ok());

        let p_start = HEADER_SIZE;
        buffer[p_start] ^= 0x01;

        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            None,
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::IncorrectCrc);

        let keys = CryptoKeys::new([0x42; 16], [0x55; 32]);

        // Checking Trusted mode.
        create_valid_frame_buffer(&mut buffer, Mode::Trusted, &payload_data);
        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            Some(&keys),
        );
        assert!(res.is_ok());

        let p_start = HEADER_SIZE;
        buffer[p_start] ^= 0x01;

        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            Some(&keys),
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::AuthFailed);

        // Checking Critical mode.
        create_valid_frame_buffer(&mut buffer, Mode::Critical, &payload_data);
        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            Some(&keys),
        );
        assert!(res.is_ok());

        let p_start = HEADER_SIZE;
        buffer[p_start] ^= 0x01;

        let res = Frame::parse::<SwIntegrityEngine, SwCryptoEngine>(
            &mut buffer,
            Some(&keys),
        );
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), Error::AuthFailed);
    }

    fn setup_frame_for_batch_tests(
        buffer: &mut [u8],
        batch_mode: bool,
        payload_len: usize,
    ) -> Frame<'_> {
        Frame::new(
            buffer,
            0xAB,
            0x00,
            payload_len,
            Flags::new()
                .with_mode(Mode::Lite)
                .with_batch(batch_mode)
                .build(),
        )
        .unwrap()
    }

    #[test]
    fn test_single_sample_mode() {
        let mut buffer = [0u8; 32];
        let mut frame = setup_frame_for_batch_tests(&mut buffer, false, 10);

        frame.push_single_sample(1000, &[0xAA, 0xBB]).unwrap();

        let payload = frame.payload().unwrap();

        assert_eq!(&payload[0..4], &[0xE8, 0x03, 0x00, 0x00]);
        assert_eq!(&payload[4..6], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_batch_delta_encoding() {
        let mut buffer = [0u8; 34];
        let mut frame = setup_frame_for_batch_tests(&mut buffer, true, 20);

        {
            let mut batch = frame.start_batch().unwrap();
            batch.push_sample(2000, &[0x11]).unwrap();
            batch.push_sample(2050, &[0x22]).unwrap();
        }

        let p = frame.payload().unwrap();
        assert_eq!(p[0], 2);

        assert_eq!(&p[1..5], &[0xD0, 0x07, 0x00, 0x00]);
        assert_eq!(p[5], 0x11);

        assert_eq!(&p[6..8], &[0x32, 0x00]);
        assert_eq!(p[8], 0x22);
    }

    #[test]
    fn test_buffer_overflow_protection() {
        let mut buffer = [0u8; 32];
        let mut frame = setup_frame_for_batch_tests(&mut buffer, false, 5);

        let err = frame.push_single_sample(12345, &[0x01, 0x02]).unwrap_err();
        assert!(matches!(err, Error::BufferOverflow));
        assert_eq!(frame.payload().unwrap()[0], 0);
    }

    fn setup_frame_for_encryption_tests(
        buffer: &mut [u8],
        encryption: bool,
        payload_len: usize,
    ) -> Frame<'_> {
        Frame::new(
            buffer,
            0xAB,
            0x00,
            payload_len,
            Flags::new()
                .with_mode(Mode::Critical)
                .with_encryption(encryption)
                .build(),
        )
        .unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut buffer = [0u8; 64];
        let original_data = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let mut frame = setup_frame_for_encryption_tests(
            &mut buffer,
            true,
            original_data.len(),
        );

        let keys = CryptoKeys::new([0x42; 16], [0x42; 32]);
        frame.set_payload_raw(&original_data, 0x7F).unwrap();
        frame.encrypt::<SwCryptoEngine>(&keys).unwrap();

        let encrypted_payload = frame.payload().unwrap();
        assert_ne!(encrypted_payload, original_data);

        frame.decrypt::<SwCryptoEngine>(&keys).unwrap();
        let decrypted_payload = frame.payload().unwrap();

        assert_eq!(decrypted_payload, original_data);
    }

    #[test]
    fn test_encrypt_without_flag_fails() {
        let mut buffer = [0u8; 64];
        let mut frame = setup_frame_for_encryption_tests(&mut buffer, false, 8);
        let keys = CryptoKeys::new([0x42; 16], [0x42; 32]);
        let res = frame.encrypt::<SwCryptoEngine>(&keys);

        assert!(matches!(res, Err(Error::InvalidOperation)));
    }

    #[test]
    fn test_nonce_changes_with_sequence() {
        let mut buffer1 = [0u8; 64];
        let mut buffer2 = [0u8; 64];
        let data = [0x55; 16];

        let mut frame1 =
            setup_frame_for_encryption_tests(&mut buffer1, true, data.len());
        frame1.payload_mut().unwrap().copy_from_slice(&data);
        frame1.header_mut().sequence = 1.into();

        let mut frame2 =
            setup_frame_for_encryption_tests(&mut buffer2, true, data.len());
        frame2.payload_mut().unwrap().copy_from_slice(&data);
        frame2.header_mut().sequence = 2.into();

        let keys = CryptoKeys::new([0x42; 16], [0x42; 32]);

        frame1.encrypt::<SwCryptoEngine>(&keys).unwrap();
        frame2.encrypt::<SwCryptoEngine>(&keys).unwrap();

        assert_ne!(frame1.payload(), frame2.payload());
    }

    #[test]
    fn test_read_single_sample_batch_mode_error() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 16).unwrap();

        frame.set_batch(true);
        assert_eq!(frame.read_single_sample(), Err(Error::InvalidOperation));
    }

    #[test]
    fn test_read_single_sample_short_payload() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 3).unwrap();

        frame.set_batch(false);
        frame
            .payload_mut()
            .unwrap()
            .copy_from_slice(&[0x01, 0x02, 0x03]);
        assert_eq!(frame.read_single_sample(), Err(Error::ParseError));
    }

    #[test]
    fn test_read_single_sample_empty_payload() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 0).unwrap();

        frame.set_batch(false);
        assert_eq!(frame.read_single_sample(), Err(Error::ParseError));
    }

    #[test]
    fn test_read_single_sample_zero_data() {
        let mut buffer = [0u8; 64];
        let payload_len = 4;
        let mut frame =
            Frame::new_lite(&mut buffer, 0x01, 0x00, payload_len).unwrap();

        let original_ts = 0xFFFF_FFFFu32;
        frame.push_single_sample(original_ts, &[]).unwrap();

        let (ts, data) = frame.read_single_sample().unwrap();

        assert_eq!(ts, original_ts);
        assert!(data.is_empty());
    }

    #[test]
    fn test_read_batch_samples_single_mode_error() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 16).unwrap();
        frame.set_batch(false);

        assert_eq!(frame.read_batch_samples(8), Err(Error::InvalidOperation));
    }

    #[test]
    fn test_read_batch_samples_empty_batch() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 1).unwrap();

        frame.set_batch(true);
        frame.payload_mut().unwrap()[0] = 0;

        let iterator = frame.read_batch_samples(8).unwrap();
        assert_eq!(iterator.count(), 0);
    }

    #[test]
    fn test_read_batch_samples_delta_reconstruction() {
        let mut buffer = [0u8; 128];
        let payload_len = 1 + 4 + 4 + 2 * (2 + 4);
        let mut frame =
            Frame::new_lite(&mut buffer, 0x01, 0x00, payload_len).unwrap();
        frame.set_batch(true);

        let mut batch = frame.start_batch().unwrap();
        batch
            .push_sample(1_000_000, &[0xAA, 0xBB, 0xCC, 0xDD])
            .unwrap();
        batch
            .push_sample(1_000_010, &[0x11, 0x22, 0x33, 0x44])
            .unwrap();
        batch
            .push_sample(1_000_025, &[0xEE, 0xFF, 0x00, 0x11])
            .unwrap();
        drop(batch);

        let iterator = frame.read_batch_samples(4).unwrap();
        let mut it = iterator;

        let s0 = it.next().ok_or("Missing sample 0").unwrap().unwrap();
        assert_eq!(s0.0, 1_000_000);

        let s1 = it.next().ok_or("Missing sample 1").unwrap().unwrap();
        assert_eq!(s1.0, 1_000_010);

        let s2 = it.next().ok_or("Missing sample 2").unwrap().unwrap();
        assert_eq!(s2.0, 1_000_025);
    }

    #[test]
    fn test_read_batch_samples_wraparound_delta() {
        let mut buffer = [0u8; 128];
        let payload_len = 1 + 4 + 4 + (2 + 4);
        let mut frame =
            Frame::new_lite(&mut buffer, 0x01, 0x00, payload_len).unwrap();
        frame.set_batch(true);

        let mut batch = frame.start_batch().unwrap();
        batch
            .push_sample(0xFFFF_FFF0u32, &[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap();
        batch
            .push_sample(0x0000_0005u32, &[0xCA, 0xFE, 0xBA, 0xBE])
            .unwrap();
        drop(batch);

        let iterator = frame.read_batch_samples(4).unwrap();
        let mut it = iterator;

        let s0 = it.next().expect("Should have first sample").unwrap();
        assert_eq!(s0.0, 0xFFFF_FFF0);

        let s1 = it.next().expect("Should have second sample").unwrap();
        assert_eq!(s1.0, 0x0000_0005);
    }

    #[test]
    fn test_read_batch_samples_malformed_payload() {
        let mut buffer = [0u8; 64];
        let mut frame = Frame::new_lite(&mut buffer, 0x01, 0x00, 10).unwrap();

        frame.set_batch(true);
        frame
            .set_payload_raw(
                &[2, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
                0x7F,
            )
            .unwrap();

        let iterator = frame.read_batch_samples(4).unwrap();
        let mut it = iterator;

        let first = it.next().expect("Iterator should not be empty");
        assert!(first.is_ok());

        let second = it.next().expect("Iterator should have a second item");
        assert!(second.is_err());
    }
}
