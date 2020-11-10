mod streamcipher;
mod aeadcipher;
mod dummy;

mod kind;
mod cipher;


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"),
    feature = "ring"
))]
mod ring;

pub use self::kind::CipherKind;
pub use self::kind::CipherCategory;
pub use self::cipher::*;
