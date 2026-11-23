# Changelog

Chafernet's Rust crate and Python packaged are versioned together.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with the
[Rust 0.x convention](https://doc.rust-lang.org/cargo/reference/semver.html).

## [0.0.1] - 2026-11-22

### Added

- Initial release: The `chafernet` Rust crate, which encrypts and decrypts Chafernet tokens (XChaCha20-Poly1305 with an encrypted timestamp, additional authenticated data, and key rotation), and the `chafernet` Python package built on it, with wheels for modern Python platforms and wasm.

[0.0.1]: https://github.com/agency-fund/chafernet/releases/tag/v0.0.1
