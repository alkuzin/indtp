// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Utils functions used across the crate.

/// Set the specific bit value.
///
/// # Parameters
/// - `value` - given value to handle.
/// - `pos` - given bit position to set.
#[inline]
pub fn set_bit(value: &mut u8, pos: u8) {
    *value |= 1 << pos;
}

/// Clear the specific bit.
///
/// # Parameters
/// - `value` - given value to handle.
/// - `pos` - given bit position to clear.
#[inline]
pub fn clear_bit(value: &mut u8, pos: u8) {
    *value &= !(1 << pos);
}

/// Change value of the specific bit.
///
/// # Parameters
/// - `value` - given value to handle.
/// - `pos` - given bit position to change.
/// - `state` - given bit state to set.
#[inline]
pub fn change_bit(value: &mut u8, pos: u8, state: bool) {
    if state {
        set_bit(value, pos);
    }
    else {
        clear_bit(value, pos);
    }
}

/// Get the specific bit value.
///
/// # Parameters
/// - `value` - given value to test.
/// - `pos` - given bit position to test.
#[inline]
pub fn test_bit(value: u8, pos: u8) -> bool {
    value & (1 << pos) != 0
}

/// Set a specific field (bits defined by a mask) to a given value.
///
/// # Parameters
/// - `value` - given value to modify.
/// - `mask` - given bitmask defining which bits to change.
/// - `field_value` - given value to write into the masked area ths is already
///   shifted to the correct position.
#[inline]
pub fn set_bit_field(value: &mut u8, mask: u8, field_value: u8) {
    *value &= !mask;
    *value |= field_value & mask;
}

/// Get the value of a specific field defined by a mask.
///
/// # Returns
/// - The extracted value.
#[inline]
pub fn get_bit_field(value: u8, mask: u8) -> u8 {
    value & mask
}

/// Create a mask for a bit field.
///
/// # Parameters
/// - `width` - given width of mask.
/// - `offset` - given offsets where mask is started.
///
/// # Returns
/// - New mask for bit field.
#[inline]
pub const fn create_mask(width: u8, offset: u8) -> u8 {
    ((1 << width) - 1) << offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_bit() {
        let mut val: u8 = 0b0000_0000;

        set_bit(&mut val, 0);
        assert_eq!(0b0000_0001, val);
        val = 0;

        set_bit(&mut val, 1);
        assert_eq!(0b0000_0010, val);
        val = 0;

        set_bit(&mut val, 5);
        assert_eq!(0b0010_0000, val);
        val = 0;

        set_bit(&mut val, 6);
        assert_eq!(0b0100_0000, val);
        val = 0;

        set_bit(&mut val, 7);
        assert_eq!(0b1000_0000, val);
    }


    #[test]
    fn test_clear_bit() {
        let mut val: u8 = 0b1111_1111;
        clear_bit(&mut val, 3);

        assert!(!test_bit(val, 3));
        assert_eq!(val, 0b1111_0111);
    }

    #[test]
    fn test_change_bit() {
        let mut val: u8 = 0b0000_0000;

        change_bit(&mut val, 5, true);
        assert!(test_bit(val, 5));

        change_bit(&mut val, 5, false);
        assert!(!test_bit(val, 5));
    }

    #[test]
    fn test_set_field_basic() {
        let mut val: u8 = 0b1111_1111;
        let mask: u8 = 0b0000_0011;

        set_bit_field(&mut val, mask, 2);
        assert_eq!(val, 0b1111_1110);
    }

    #[test]
    fn test_set_field_protects_overflow() {
        let mut val: u8 = 0;
        let mask: u8 = 0b0000_0011;

        set_bit_field(&mut val, mask, 5);
        assert_eq!(val, 1);
    }

    #[test]
    fn test_create_mask() {
        assert_eq!(create_mask(2, 0), 0b0000_0011);
        assert_eq!(create_mask(3, 4), 0b0111_0000);
        assert_eq!(create_mask(1, 7), 0b1000_0000);
    }
}
