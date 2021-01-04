//! Shadowsocks V1 protocol ciphers

#[cfg(feature = "v1_aead")]
mod aeadcipher;
mod dummy;
#[cfg(feature = "v1_stream")]
mod streamcipher;

mod cipher;
mod kind;

#[cfg(all(
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ),
    feature = "ring",
    feature = "v1_aead",
))]
mod ring;

pub use self::cipher::*;
pub use self::kind::CipherCategory;
pub use self::kind::CipherKind;
