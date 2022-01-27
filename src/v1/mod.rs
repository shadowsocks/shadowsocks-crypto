//! Shadowsocks V1 protocol ciphers

#[cfg(feature = "v1-aead")]
mod aeadcipher;
mod dummy;
#[cfg(feature = "v1-stream")]
mod streamcipher;

mod cipher;
mod kind;

pub use self::{
    cipher::*,
    kind::{CipherCategory, CipherKind},
};
