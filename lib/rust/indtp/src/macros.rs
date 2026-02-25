// SPDX-License-Identifier: Apache-2.0.
// Copyright (C) 2026-present indtp project and contributors.

//! Macros utilities.

/// Apply some traits for INDTP struct declarations.
#[macro_export]
macro_rules! indtp_data {
    ($($item:item)*) => {
        $(
            #[derive(
                Clone, Copy,
                $crate::prelude::IntoBytes,
                $crate::prelude::FromBytes,
                $crate::prelude::Immutable,
                $crate::prelude::KnownLayout,
            )]
            #[repr(C, packed)]
            $item
        )*
    };
}
