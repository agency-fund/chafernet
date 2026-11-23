#![doc = include_str!("crate-docs.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod aad;
mod keyset;
mod token;

pub use aad::{Aad, Context};
pub use keyset::{KEY_LEN, Key, KeyError, Keyset, KeysetError};
pub use token::{
    AadState, Chafernet, DEFAULT_MAX_CLOCK_SKEW, Decrypt, Encrypt, InvalidToken, NoAad,
    PLAINTEXT_FORMAT_VERSION, WithAad,
};
