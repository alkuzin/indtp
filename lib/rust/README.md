# indtp - Rust implementation of Inertial Navigation Data Transfer Protocol (INDTP)

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
indtp = { git = "https://github.com/alkuzin/indtp" }
```

Build project:

```shell
cargo build --release
```

## ⚙️ Features

- `sw_integrity` - enable software-based calculation for integrity checks.
- `sw_crypto` - enable software-based calculation for cryptography.
- `std_payloads` - Feature that enables standard payloads.
- `sw_impl` - enable software-based calculation for integrity checks and cryptography.

> Crate enabling some features by default:

- `sw_impl`;
- `std_payloads`.

In order to disable them (if needed) use:

```toml
[dependencies]
indtp = { ..., default-features = false, features = ["<features that you actually need>"] }
```

## 🚀 Examples

Run examples:

```shell
# Basic usage eample.
cargo run --example basic

# Data aggregation example.
cargo run --example batching

# Payload encryption example.
cargo run --example encrypt
```

## 🛠 Custom Payloads

While INDTP supports several standard payloads that cover most use cases, it does not limit the **creation of custom payloads** for specific devices.
Creation of the payload struct for custom IMU device is quite simple:

```rust

indtp_data! {
    pub struct CustomPayload {
        pub acc_x: f32,
        pub acc_y: f32,
        pub acc_z: f32,
        pub baro: f32,
        /// Other metrics here...
    }
}

impl Packable for CustomPayload {}

impl Payload for CustomPayload  {
    // `PAYLOAD_ID` - is your custom payload type identifier
    // within range 0x80-0xFF - for vendor-specific types.
    const TYPE_ID: u8 = PAYLOAD_ID;
}

```

That's all. No need for manual serialization/deserialization, size calculation etc. `Payload` handles that.

## ⚒️ Tests

Run all tests:

```shell
cargo test
```

## 📚 Documentation

Generate & open crate documentation:

```shell
cargo doc --open
```

## 📜 License

Copyright (C) 2026-present indtp project and contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
