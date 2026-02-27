// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Utility functions.

/// Validates if a received sequence number is newer than the last accepted one.
///
/// Implements INDTP Specification v1.0:
/// Section 4.6 "Sequence Number Wrap-Around Handling".
///
/// # Parameters
/// - `recv_seq` - given sequence number from the incoming frame.
/// - `last_seq` - given sequence number of the last successfully processed frame.
///
/// # Returns
/// - `true` - if the packet is new and should be processed.
/// - `false` - if the packet is old, duplicate, or a replay attack.
#[inline]
pub fn is_sequence_correct(recv_seq: u16, last_seq: Option<u16>) -> bool {
    match last_seq {
        None => true,
        Some(last) => {
            let diff = recv_seq.wrapping_sub(last) as i16;
            diff > 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_sequence() {
        assert_eq!(is_sequence_correct(0, None), true);
        assert_eq!(is_sequence_correct(123, None), true);
    }

    #[test]
    fn test_normal_increment() {
        assert!(is_sequence_correct(101, Some(100)));
        assert!(is_sequence_correct(200, Some(100)));
    }

    #[test]
    fn test_exact_duplicate() {
        assert!(!is_sequence_correct(100, Some(100)));
    }

    #[test]
    fn test_wrap_around() {
        assert!(is_sequence_correct(0, Some(65535)));
        assert!(is_sequence_correct(1, Some(65535)));
        assert!(is_sequence_correct(65535, Some(65534)));
    }

    #[test]
    fn test_replay_attack() {
        assert!(!is_sequence_correct(100, Some(105)));
        assert!(!is_sequence_correct(65535, Some(5)));
    }
}
