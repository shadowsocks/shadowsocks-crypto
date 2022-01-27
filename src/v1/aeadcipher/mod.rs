use crate::v1::CipherKind;

mod aes_gcm;
#[cfg(feature = "v1-aead-extra")]
mod aes_gcm_siv;
mod chacha20_poly1305;
#[cfg(feature = "v1-aead-extra")]
mod xchacha20_poly1305;

pub use self::{
    aes_gcm::{Aes128Gcm, Aes256Gcm},
    chacha20_poly1305::ChaCha20Poly1305,
};
#[cfg(feature = "v1-aead-extra")]
pub use self::{
    aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv},
    xchacha20_poly1305::XChaCha20Poly1305,
};

enum AeadCipherVariant {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
    #[cfg(feature = "v1-aead-extra")]
    XChaCha20Poly1305(XChaCha20Poly1305),
    #[cfg(feature = "v1-aead-extra")]
    Aes128GcmSiv(Aes128GcmSiv),
    #[cfg(feature = "v1-aead-extra")]
    Aes256GcmSiv(Aes256GcmSiv),
}

impl AeadCipherVariant {
    fn new(kind: CipherKind, key: &[u8]) -> AeadCipherVariant {
        match kind {
            CipherKind::AES_128_GCM => AeadCipherVariant::Aes128Gcm(Aes128Gcm::new(key)),
            CipherKind::AES_256_GCM => AeadCipherVariant::Aes256Gcm(Aes256Gcm::new(key)),
            CipherKind::CHACHA20_POLY1305 => AeadCipherVariant::ChaCha20Poly1305(ChaCha20Poly1305::new(key)),
            #[cfg(feature = "v1-aead-extra")]
            CipherKind::XCHACHA20_POLY1305 => AeadCipherVariant::XChaCha20Poly1305(XChaCha20Poly1305::new(key)),
            #[cfg(feature = "v1-aead-extra")]
            CipherKind::AES_128_GCM_SIV => AeadCipherVariant::Aes128GcmSiv(Aes128GcmSiv::new(key)),
            #[cfg(feature = "v1-aead-extra")]
            CipherKind::AES_256_GCM_SIV => AeadCipherVariant::Aes256GcmSiv(Aes256GcmSiv::new(key)),
            _ => unreachable!("{:?} is not an AEAD cipher", kind),
        }
    }

    fn nonce_size(&self) -> usize {
        match *self {
            AeadCipherVariant::Aes128Gcm(..) => Aes128Gcm::nonce_size(),
            AeadCipherVariant::Aes256Gcm(..) => Aes256Gcm::nonce_size(),
            AeadCipherVariant::ChaCha20Poly1305(..) => ChaCha20Poly1305::nonce_size(),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::XChaCha20Poly1305(..) => XChaCha20Poly1305::nonce_size(),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes128GcmSiv(..) => Aes128GcmSiv::nonce_size(),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes256GcmSiv(..) => Aes256GcmSiv::nonce_size(),
        }
    }

    fn kind(&self) -> CipherKind {
        match *self {
            AeadCipherVariant::Aes128Gcm(..) => CipherKind::AES_128_GCM,
            AeadCipherVariant::Aes256Gcm(..) => CipherKind::AES_256_GCM,
            AeadCipherVariant::ChaCha20Poly1305(..) => CipherKind::CHACHA20_POLY1305,
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::XChaCha20Poly1305(..) => CipherKind::XCHACHA20_POLY1305,
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes128GcmSiv(..) => CipherKind::AES_128_GCM_SIV,
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes256GcmSiv(..) => CipherKind::AES_256_GCM_SIV,
        }
    }

    fn encrypt(&mut self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        match *self {
            AeadCipherVariant::Aes128Gcm(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            AeadCipherVariant::Aes256Gcm(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            AeadCipherVariant::ChaCha20Poly1305(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::XChaCha20Poly1305(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes128GcmSiv(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes256GcmSiv(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
        }
    }

    fn decrypt(&mut self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match *self {
            AeadCipherVariant::Aes128Gcm(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            AeadCipherVariant::Aes256Gcm(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            AeadCipherVariant::ChaCha20Poly1305(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::XChaCha20Poly1305(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes128GcmSiv(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            #[cfg(feature = "v1-aead-extra")]
            AeadCipherVariant::Aes256GcmSiv(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
        }
    }
}

pub struct AeadCipher {
    cipher: AeadCipherVariant,
    nlen: usize,
    nonce: [u8; Self::N_MAX],
}

impl AeadCipher {
    const N_MAX: usize = 24;

    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        let cipher = AeadCipherVariant::new(kind, key);
        let nlen = cipher.nonce_size();
        debug_assert!(nlen <= Self::N_MAX);
        let nonce = [0u8; Self::N_MAX];

        Self { cipher, nlen, nonce }
    }

    #[inline(always)]
    pub fn kind(&self) -> CipherKind {
        self.cipher.kind()
    }

    #[inline(always)]
    pub fn tag_len(&self) -> usize {
        self.cipher.kind().tag_len()
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
        self.cipher.encrypt(nonce, plaintext_in_ciphertext_out);
        self.increase_nonce();
    }

    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self.cipher.decrypt(nonce, ciphertext_in_plaintext_out);
        self.increase_nonce();
        ret
    }
}
