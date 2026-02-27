// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! INDTP batch implementation.

use crate::{Frame, prelude::*};

/// Active batch record context.
pub struct Batch<'b, 'a> {
    /// INDTP frame reference.
    frame: &'b mut Frame<'a>,
    /// Total number of samples.
    sample_count: u8,
    /// Current offset inside offset.
    offset: usize,
    /// Previous timestamp.
    prev_timestamp: u32,
}

impl<'b, 'a> Batch<'b, 'a> {
    /// Construct new batch.
    ///
    /// # Parameters
    /// - `frame` - given INDTP frame reference to handle.
    ///
    /// # Returns
    /// - New active batch record context.
    pub fn new(frame: &'b mut Frame<'a>) -> Self {
        Self {
            frame,
            sample_count: 0,
            offset: 0,
            prev_timestamp: 0,
        }
    }

    /// Push sample into the batch.
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
    /// - Buffer overflow.
    /// - Parse errors.
    pub fn push_sample(&mut self, timestamp: u32, data: &[u8]) -> Result<()> {
        let is_first = self.sample_count == 0;
        let timestamp_size = if is_first { 4 } else { 2 };

        let required_len = 1 + self.offset + timestamp_size + data.len();

        if required_len > self.frame.payload_len() {
            return Err(Error::BufferOverflow);
        }

        let payload = self.frame.payload_mut()?;
        let current_pos = 1 + self.offset;

        if is_first {
            // First sample contains an absolute timestamp (u32).
            payload
                .get_mut(current_pos..current_pos + 4)
                .ok_or(Error::ParseError)?
                .copy_from_slice(&timestamp.to_le_bytes());

            self.offset += 4;
        } else {
            // Other samples contain relative delta-time (u16) since previous
            // sample followed by sensor data.
            let delta = timestamp.wrapping_sub(self.prev_timestamp) as u16;

            payload
                .get_mut(current_pos..current_pos + 2)
                .ok_or(Error::ParseError)?
                .copy_from_slice(&delta.to_le_bytes());

            self.offset += 2;
        }

        self.prev_timestamp = timestamp;

        // Handling sample data.
        let data_start = current_pos + timestamp_size;

        payload
            .get_mut(data_start..data_start + data.len())
            .ok_or(Error::ParseError)?
            .copy_from_slice(data);

        self.offset += data.len();
        self.sample_count += 1;

        Ok(())
    }
}

impl<'b, 'a> Drop for Batch<'b, 'a> {
    /// Batch destructor.
    fn drop(&mut self) {
        if self.sample_count > 0
            && let Ok(payload) = self.frame.payload_mut()
            && let Some(first_byte) = payload.get_mut(0)
        {
            *first_byte = self.sample_count;
        }
    }
}

/// Iterator over batched samples in INDTP payload.
#[derive(Debug, PartialEq)]
pub struct BatchIterator<'a> {
    /// Reference to payload bytes.
    payload: &'a [u8],
    /// Total number of samples.
    sample_count: u8,
    /// Current sample index.
    current_idx: u8,
    /// Current byte offset in payload.
    offset: usize,
    /// Previous timestamp.
    prev_timestamp: u32,
    /// Size of sensor data per sample in bytes.
    sample_size: usize,
}

impl<'a> BatchIterator<'a> {
    /// Create new batch iterator.
    ///
    /// # Parameters
    /// - `payload` - given reference to payload bytes.
    /// - `sample_size` - given size of sensor data portion per sample in bytes.
    ///
    /// # Returns
    /// - New batch iterator - in case of success.
    /// - `Err` - otherwise.
    ///
    /// # Errors
    /// - Parse errors.
    pub fn new(payload: &'a [u8], sample_size: usize) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::ParseError);
        }

        let sample_count = *payload.first().ok_or(Error::ParseError)?;

        if sample_count > 0 && payload.len() < 5 {
            return Err(Error::ParseError);
        }

        Ok(Self {
            payload,
            sample_count,
            current_idx: 0,
            offset: 1,
            prev_timestamp: 0,
            sample_size,
        })
    }
}

impl<'a> Iterator for BatchIterator<'a> {
    type Item = Result<(u32, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_idx >= self.sample_count {
            return None;
        }

        let is_first = self.current_idx == 0;
        let timestamp_size = if is_first { 4 } else { 2 };

        if self.offset + timestamp_size > self.payload.len() {
            return Some(Err(Error::ParseError));
        }

        let timestamp = if is_first {
            // Handling an absolute timestamp in first sample.
            let timestamp_bytes: [u8; 4] = self
                .payload
                .get(self.offset..self.offset + 4)
                .ok_or(Error::ParseError)
                .ok()?
                .try_into()
                .ok()?;

            let timestamp = u32::from_le_bytes(timestamp_bytes);
            self.prev_timestamp = timestamp;
            timestamp
        } else {
            //  Handling delta timestamp in other samples.
            let delta_bytes: [u8; 2] = self
                .payload
                .get(self.offset..self.offset + 2)
                .ok_or(Error::ParseError)
                .ok()?
                .try_into()
                .ok()?;

            let delta = u16::from_le_bytes(delta_bytes);
            let timestamp = self.prev_timestamp.wrapping_add(u32::from(delta));
            self.prev_timestamp = timestamp;
            timestamp
        };

        self.offset += timestamp_size;

        if self.offset + self.sample_size > self.payload.len() {
            return Some(Err(Error::ParseError));
        }

        let data = &self
            .payload
            .get(self.offset..self.offset + self.sample_size)
            .ok_or(Error::ParseError)
            .ok()?;

        self.offset += self.sample_size;
        self.current_idx += 1;

        Some(Ok((timestamp, data)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.sample_count - self.current_idx);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BatchIterator<'a> {}
