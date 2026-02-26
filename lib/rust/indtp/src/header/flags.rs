// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Protocol flags related declarations.

use bitflags::bitflags;
use crate::Mode;

bitflags! {
    /// Protocol flags type-safe wrapper.
    #[derive(PartialEq, Eq, Clone, Copy, Default)]
    pub struct Flags: u8 {
        /// Mode for minimum latency and overhead for trusted internal channels.
        const MODE_LITE = 0b0000_0000;

        /// Robust data transmission in noisy environments with protection against
        /// accidental corruption.
        const MODE_VERIFIED = 0b0000_0001;

        /// Balanced security for unsecured wireless channels.
        /// Provides protection against data spoofing and replay attacks with
        /// minimal overhead.
        const MODE_TRUSTED = 0b0000_0010;

        /// Maximum security for critical commands, firmware updates, or
        /// configuration changes where bandwidth is secondary to trust.
        const MODE_CRITICAL = 0b0000_0011;

        /// Payload mode bit mask.
        const MODE_MASK = 0b0000_0011;

        /// Batching flag:
        /// - `0`: Single sample mode. Payload contains one data record with
        /// an absolute timestamp;
        /// - `1`: Batch mode. Payload section starts with count `N`, followed by
        /// `N` records with relative timestamps.
        const BATCH = 1 << 2;

        /// Payload encryption flag:
        /// - `0`: Payload is not encrypted;
        /// - `1`: Payload is encrypted using `AES-128-CTR`.
        const ENCRYPT = 1 << 3;

        /// Frame handling priority flag:
        /// - `0`: Low priority.
        /// - `1`: High priority.
        const PRIORITY = 1 << 4;
    }
}

impl Flags {
    /// Create an empty set of flags.
    ///
    /// # Returns
    /// - New empty set of flags.
    #[inline]
    pub const fn new() -> Self {
        Self::empty()
    }

    /// Set the protocol operating mode.
    ///
    /// # Parameters
    /// - `mode` - given protocol operating mode to set.
    ///
    /// # Returns
    /// - Updated set of flags.
    #[inline]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        let flag = match mode {
            Mode::Lite => Self::MODE_LITE,
            Mode::Verified => Self::MODE_VERIFIED,
            Mode::Trusted => Self::MODE_TRUSTED,
            Mode::Critical => Self::MODE_CRITICAL,
        };

        self.remove(Self::MODE_MASK);
        self.insert(flag);
        self
    }

    /// Enable or disable the `BATCH` flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    ///
    /// # Returns
    /// - Updated set of flags.
    #[inline]
    pub fn with_batch(mut self, enabled: bool) -> Self {
        if enabled {
            self.insert(Self::BATCH);
        } else {
            self.remove(Self::BATCH);
        }
        self
    }

    /// Enable or disable the `ENCRYPT` flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    ///
    /// # Returns
    /// - Updated set of flags.
    #[inline]
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        if enabled {
            self.insert(Self::ENCRYPT);
        } else {
            self.remove(Self::ENCRYPT);
        }
        self
    }

    /// Enable or disable the `PRIORITY` flag.
    ///
    /// # Parameters
    /// - `enabled` - given flag to handle.
    ///
    /// # Returns
    /// - Updated set of flags.
    #[inline]
    pub fn with_priority(mut self, enabled: bool) -> Self {
        if enabled {
            self.insert(Self::PRIORITY);
        } else {
            self.remove(Self::PRIORITY);
        }
        self
    }

    /// Finalize the build.
    ///
    /// # Returns
    /// - Updated set of flags.
    #[inline]
    pub const fn build(self) -> Self {
        self
    }
}
