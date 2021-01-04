pub use crypto2::aeadcipher::{
    Aes128Ccm, Aes128GcmSiv, Aes128OcbTag128, Aes192OcbTag128, Aes256Ccm, Aes256GcmSiv,
    Aes256OcbTag128, AesSivCmac256, AesSivCmac384, AesSivCmac512,
};
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
pub use super::ring::{Aes128Gcm, Aes256Gcm, Chacha20Poly1305};
use super::CipherKind;

trait AeadCipherInner {
    fn ac_kind(&self) -> CipherKind;
    fn ac_key_len(&self) -> usize;
    fn ac_block_len(&self) -> usize;
    fn ac_n_min(&self) -> usize;
    fn ac_n_max(&self) -> usize;
    fn ac_tag_len(&self) -> usize;

    fn ac_encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]);
    fn ac_decrypt_slice(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool;
}

macro_rules! impl_aead_cipher {
    ($name:tt, $kind:tt) => {
        impl AeadCipherInner for $name {
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
}

macro_rules! impl_siv_cmac_cipher {
    ($name:tt, $kind:tt) => {
        impl AeadCipherInner for $name {
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

            // NOTE: SIV-CMAC 模式，Nonce 在 AAD 数据的最后面。
            //       TAG 默认也在 PKT 的前面，为此我们这里需要手动把 TAG 数据放置在 密文的后面。
            fn ac_encrypt_slice(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let len = plaintext_in_ciphertext_out.len();
                let plen = len - Self::TAG_LEN;
                let (plaintext, tag_out) = plaintext_in_ciphertext_out.split_at_mut(plen);
                self.encrypt_slice_detached(&[nonce], plaintext, tag_out);
            }

            fn ac_decrypt_slice(
                &self,
                nonce: &[u8],
                ciphertext_in_plaintext_out: &mut [u8],
            ) -> bool {
                let len = ciphertext_in_plaintext_out.len();
                let clen = len - Self::TAG_LEN;
                let (ciphertext, tag_in) = ciphertext_in_plaintext_out.split_at_mut(clen);
                self.decrypt_slice_detached(&[nonce], ciphertext, &tag_in)
            }
        }
    };
}

impl_aead_cipher!(Aes128Ccm, AES_128_CCM);
impl_aead_cipher!(Aes256Ccm, AES_256_CCM);
impl_aead_cipher!(Aes128Gcm, AES_128_GCM);
impl_aead_cipher!(Aes256Gcm, AES_256_GCM);

impl_aead_cipher!(Aes128GcmSiv, AES_128_GCM_SIV);
impl_aead_cipher!(Aes256GcmSiv, AES_256_GCM_SIV);

impl_aead_cipher!(Aes128OcbTag128, AES_128_OCB_TAGLEN128);
impl_aead_cipher!(Aes192OcbTag128, AES_192_OCB_TAGLEN128);
impl_aead_cipher!(Aes256OcbTag128, AES_256_OCB_TAGLEN128);

impl_aead_cipher!(Chacha20Poly1305, CHACHA20_POLY1305);

impl_siv_cmac_cipher!(AesSivCmac256, AES_SIV_CMAC_256);
impl_siv_cmac_cipher!(AesSivCmac384, AES_SIV_CMAC_384);
impl_siv_cmac_cipher!(AesSivCmac512, AES_SIV_CMAC_512);

pub struct AeadCipher {
    cipher: Box<dyn AeadCipherInner + Send + 'static>,
    nlen: usize,
    nonce: [u8; Self::N_MAX],
}

impl AeadCipher {
    const N_MAX: usize = 16;

    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        use self::CipherKind::*;

        let cipher: Box<dyn AeadCipherInner + Send + 'static> = match kind {
            AES_128_CCM => Box::new(Aes128Ccm::new(key)),
            AES_256_CCM => Box::new(Aes256Ccm::new(key)),
            AES_128_OCB_TAGLEN128 => Box::new(Aes128OcbTag128::new(key)),
            AES_192_OCB_TAGLEN128 => Box::new(Aes192OcbTag128::new(key)),
            AES_256_OCB_TAGLEN128 => Box::new(Aes256OcbTag128::new(key)),
            AES_128_GCM => Box::new(Aes128Gcm::new(key)),
            AES_256_GCM => Box::new(Aes256Gcm::new(key)),
            AES_SIV_CMAC_256 => Box::new(AesSivCmac256::new(key)),
            AES_SIV_CMAC_384 => Box::new(AesSivCmac384::new(key)),
            AES_SIV_CMAC_512 => Box::new(AesSivCmac512::new(key)),
            AES_128_GCM_SIV => Box::new(Aes128GcmSiv::new(key)),
            AES_256_GCM_SIV => Box::new(Aes256GcmSiv::new(key)),
            CHACHA20_POLY1305 => Box::new(Chacha20Poly1305::new(key)),
            _ => unreachable!(),
        };

        let nlen = std::cmp::min(cipher.ac_n_max(), Self::N_MAX);

        let nonce = [0u8; Self::N_MAX];

        Self {
            cipher,
            nonce,
            nlen,
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
