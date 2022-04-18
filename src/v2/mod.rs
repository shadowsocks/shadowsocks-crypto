//! AEAD 2022 Ciphers

pub(crate) mod crypto;
pub mod tcp;
pub mod udp;

/// AEAD2022 protocol Blake3 KDF context
pub const BLAKE3_KEY_DERIVE_CONTEXT: &str = "shadowsocks 2022 session subkey";
