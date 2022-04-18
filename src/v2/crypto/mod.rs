//! AEAD 2022 Cryptographic Algorithms

pub use self::{
    aes_gcm::{Aes128Gcm, Aes256Gcm},
    chacha20_poly1305::ChaCha20Poly1305,
    xchacha20_poly1305::XChaCha20Poly1305,
};

pub mod aes_gcm;
pub mod chacha20_poly1305;
#[allow(dead_code)]
pub mod xchacha20_poly1305;
