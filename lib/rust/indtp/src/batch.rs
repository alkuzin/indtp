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
