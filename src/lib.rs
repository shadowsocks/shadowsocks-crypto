//! Shadowsocks Cipher implementation

#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

pub mod kind;
pub mod utils;

pub use self::kind::{CipherCategory, CipherKind};

/// Get available ciphers in string representation
///
/// Commonly used for checking users' configuration input
pub const fn available_ciphers() -> &'static [&'static str] {
    &[
        "plain",
        "none",
        #[cfg(feature = "v1-stream")]
        "table",
        #[cfg(feature = "v1-stream")]
        "rc4-md5",
        // Stream Ciphers
        #[cfg(feature = "v1-stream")]
        "aes-128-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-192-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-256-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-128-ofb",
        #[cfg(feature = "v1-stream")]
        "aes-192-ofb",
        #[cfg(feature = "v1-stream")]
        "aes-256-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-128-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-192-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-256-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-128-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-192-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-256-ofb",
        #[cfg(feature = "v1-stream")]
        "rc4",
        #[cfg(feature = "v1-stream")]
        "chacha20-ietf",
        // AEAD Ciphers
        #[cfg(feature = "v1-aead")]
        "aes-128-gcm",
        #[cfg(feature = "v1-aead")]
        "aes-256-gcm",
        #[cfg(feature = "v1-aead")]
        "chacha20-ietf-poly1305",
        #[cfg(feature = "v1-aead-extra")]
        "aes-128-ccm",
        #[cfg(feature = "v1-aead-extra")]
        "aes-256-ccm",
        #[cfg(feature = "v1-aead-extra")]
        "aes-128-gcm-siv",
        #[cfg(feature = "v1-aead-extra")]
        "aes-256-gcm-siv",
        #[cfg(feature = "v1-aead-extra")]
        "xchacha20-ietf-poly1305",
        // #[cfg(feature = "v1-aead-extra")]
        // "sm4-gcm",
        // #[cfg(feature = "v1-aead-extra")]
        // "sm4-ccm",
        // AEAD 2022 Ciphers
        #[cfg(feature = "v2")]
        "2022-blake3-aes-128-gcm",
        #[cfg(feature = "v2")]
        "2022-blake3-aes-256-gcm",
        #[cfg(feature = "v2")]
        "2022-blake3-chacha20-poly1305",
        #[cfg(feature = "v2-extra")]
        "2022-blake3-chacha8-poly1305",
    ]
}
