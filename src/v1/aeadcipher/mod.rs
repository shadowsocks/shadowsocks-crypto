pub use crypto2::aeadcipher::{Aes128Ccm, Aes128GcmSiv, Aes256Ccm, Aes256GcmSiv, Sm4Ccm, Sm4Gcm};
#[cfg(not(all(
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ),
    feature = "ring"
)))]
pub use crypto2::aeadcipher::{Aes128Gcm, Aes256Gcm, Chacha20Poly1305};

#[cfg(all(
    any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ),
    feature = "ring"
))]
pub use crate::v1::ring::{Aes128Gcm, Aes256Gcm, Chacha20Poly1305};
use crate::v1::CipherKind;

#[cfg(feature = "v1-aead-extra")]
pub mod xchacha20_poly1305;
#[cfg(feature = "v1-aead-extra")]
pub use self::xchacha20_poly1305::XChacha20Poly1305;

trait AeadCipherExt {
    fn ac_kind(&self) -> CipherKind;
    fn ac_key_len(&self) -> usize;
    fn ac_block_len(&self) -> usize;
    fn ac_n_min(&self) -> usize;
    fn ac_n_max(&self) -> usize;
    fn ac_tag_len(&self) -> usize;
    fn ac_n_len(&self) -> usize;

    fn ac_encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]);
    fn ac_decrypt_slice(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool;
}

macro_rules! impl_aead_cipher {
    ($name:tt, $kind:tt $(, $nlen:expr)?) => {
        impl AeadCipherExt for $name {
            fn ac_kind(&self) -> CipherKind {
                CipherKind::$kind
            }
            fn ac_key_len(&self) -> usize {
                $name::KEY_LEN
            }
            fn ac_block_len(&self) -> usize {
                $name::BLOCK_LEN
            }
            fn ac_n_min(&self) -> usize {
                $name::N_MIN
            }
            fn ac_n_max(&self) -> usize {
                $name::N_MAX
            }
            fn ac_tag_len(&self) -> usize {
                $name::TAG_LEN
            }
            impl_aead_cipher!(ac_n_len $(, $nlen)?);

            fn ac_encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                self.encrypt_slice(nonce, &[], plaintext_in_ciphertext_out);
            }

            fn ac_decrypt_slice(
                &self,
                nonce: &[u8],
                ciphertext_in_plaintext_out: &mut [u8],
            ) -> bool {
                self.decrypt_slice(nonce, &[], ciphertext_in_plaintext_out)
            }
        }
    };

    (ac_n_len) => {
        fn ac_n_len(&self) -> usize {
            debug_assert_eq!(self.ac_n_min(), self.ac_n_max());
            self.ac_n_max()
        }
    };
    (ac_n_len, $nlen:expr) => {
        fn ac_n_len(&self) -> usize {
            debug_assert!($nlen >= self.ac_n_min() && $nlen <= self.ac_n_max());
            $nlen
        }
    };
}

#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Aes128Ccm, AES_128_CCM);
#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Aes256Ccm, AES_256_CCM);

impl_aead_cipher!(Aes128Gcm, AES_128_GCM);
impl_aead_cipher!(Aes256Gcm, AES_256_GCM);

#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Aes128GcmSiv, AES_128_GCM_SIV);
#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Aes256GcmSiv, AES_256_GCM_SIV);

impl_aead_cipher!(Chacha20Poly1305, CHACHA20_POLY1305);

#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(XChacha20Poly1305, XCHACHA20_POLY1305);

#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Sm4Gcm, SM4_GCM);
#[cfg(feature = "v1-aead-extra")]
impl_aead_cipher!(Sm4Ccm, SM4_CCM);

macro_rules! aead_cipher_variant {
    ($($(#[cfg($i_meta:meta)])? $name:ident @ $kind:ident,)+) => {
        enum AeadCipherInner {
            $(
                $(#[cfg($i_meta)])?
                $name($name),
            )+
        }

        impl AeadCipherInner {
            fn new(kind: CipherKind, key: &[u8]) -> Self {
                match kind {
                    $(
                        $(#[cfg($i_meta)])?
                        CipherKind::$kind => AeadCipherInner::$name($name::new(key)),
                    )+
                    _ => unreachable!("unrecognized AEAD cipher kind {:?}", kind),
                }
            }
        }

        impl AeadCipherExt for AeadCipherInner {
            fn ac_kind(&self) -> CipherKind {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_kind(),
                    )+
                }
            }

            fn ac_key_len(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_key_len(),
                    )+
                }
            }
            fn ac_block_len(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_block_len(),
                    )+
                }
            }

            fn ac_tag_len(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_tag_len(),
                    )+
                }
            }

            fn ac_n_min(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_n_min(),
                    )+
                }
            }
            fn ac_n_max(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_n_max(),
                    )+
                }
            }
            fn ac_n_len(&self) -> usize {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_n_len(),
                    )+
                }
            }

            fn ac_encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_encrypt_slice(nonce, plaintext_in_ciphertext_out),
                    )+
                }
            }

            fn ac_decrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) -> bool {
                match *self {
                    $(
                        $(#[cfg($i_meta)])?
                        AeadCipherInner::$name(ref c) => c.ac_decrypt_slice(nonce, plaintext_in_ciphertext_out),
                    )+
                }
            }
        }
    };
}

aead_cipher_variant! {
    #[cfg(feature = "v1-aead-extra")] Aes128Ccm @ AES_128_CCM,
    #[cfg(feature = "v1-aead-extra")] Aes256Ccm @ AES_256_CCM,

    Aes128Gcm @ AES_128_GCM,
    Aes256Gcm @ AES_256_GCM,

    #[cfg(feature = "v1-aead-extra")] Aes128GcmSiv @ AES_128_GCM_SIV,
    #[cfg(feature = "v1-aead-extra")] Aes256GcmSiv @ AES_256_GCM_SIV,

    Chacha20Poly1305 @ CHACHA20_POLY1305,

    #[cfg(feature = "v1-aead-extra")] XChacha20Poly1305 @ XCHACHA20_POLY1305,

    #[cfg(feature = "v1-aead-extra")] Sm4Gcm @ SM4_GCM,
    #[cfg(feature = "v1-aead-extra")] Sm4Ccm @ SM4_CCM,
}

pub struct AeadCipher {
    cipher: AeadCipherInner,
    nlen: usize,
    nonce: [u8; Self::N_MAX],
}

impl AeadCipher {
    const N_MAX: usize = 24;

    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        let cipher = AeadCipherInner::new(kind, key);
        let nlen = cipher.ac_n_len();
        debug_assert!(nlen <= Self::N_MAX);
        let nonce = [0u8; Self::N_MAX];

        Self {
            cipher,
            nlen,
            nonce,
        }
    }

    pub fn kind(&self) -> CipherKind {
        self.cipher.ac_kind()
    }

    pub fn tag_len(&self) -> usize {
        self.cipher.ac_tag_len()
    }

    #[inline]
    fn increase_nonce(&mut self) {
        let mut c = self.nonce[0] as u16 + 1;
        self.nonce[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < self.nlen {
            c += self.nonce[n] as u16;
            self.nonce[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }

    pub fn encrypt(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = &self.nonce[..self.nlen];
        self.cipher
            .ac_encrypt_slice(nonce, plaintext_in_ciphertext_out);
        self.increase_nonce();
    }

    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self
            .cipher
            .ac_decrypt_slice(nonce, ciphertext_in_plaintext_out);
        self.increase_nonce();
        ret
    }
}
