//! AEAD 2022 TCP Ciphers

use crate::{
    kind::{CipherCategory, CipherKind},
    v2::{
        crypto::{
            aes_gcm::{Aes128Gcm, Aes256Gcm},
            chacha20_poly1305::ChaCha20Poly1305,
        },
        BLAKE3_KEY_DERIVE_CONTEXT,
    },
};

enum CipherVariant {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl CipherVariant {
    fn new(kind: CipherKind, key: &[u8]) -> CipherVariant {
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => CipherVariant::Aes128Gcm(Aes128Gcm::new(key)),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => CipherVariant::Aes256Gcm(Aes256Gcm::new(key)),
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                CipherVariant::ChaCha20Poly1305(ChaCha20Poly1305::new(key))
            }
            _ => unreachable!("{:?} is not an AEAD cipher", kind),
        }
    }

    fn nonce_size(&self) -> usize {
        match *self {
            CipherVariant::Aes128Gcm(..) => Aes128Gcm::nonce_size(),
            CipherVariant::Aes256Gcm(..) => Aes256Gcm::nonce_size(),
            CipherVariant::ChaCha20Poly1305(..) => ChaCha20Poly1305::nonce_size(),
        }
    }

    fn kind(&self) -> CipherKind {
        match *self {
            CipherVariant::Aes128Gcm(..) => CipherKind::AEAD2022_BLAKE3_AES_128_GCM,
            CipherVariant::Aes256Gcm(..) => CipherKind::AEAD2022_BLAKE3_AES_256_GCM,
            CipherVariant::ChaCha20Poly1305(..) => CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
        }
    }

    fn encrypt(&mut self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        match *self {
            CipherVariant::Aes128Gcm(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            CipherVariant::Aes256Gcm(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
            CipherVariant::ChaCha20Poly1305(ref mut c) => c.encrypt(nonce, plaintext_in_ciphertext_out),
        }
    }

    fn decrypt(&mut self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match *self {
            CipherVariant::Aes128Gcm(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            CipherVariant::Aes256Gcm(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
            CipherVariant::ChaCha20Poly1305(ref mut c) => c.decrypt(nonce, ciphertext_in_plaintext_out),
        }
    }
}

/// AEAD2022 TCP Cipher
pub struct TcpCipher {
    cipher: CipherVariant,
    nlen: usize,
    nonce: [u8; Self::N_MAX],
}

impl TcpCipher {
    /// Maximum length of nonce
    const N_MAX: usize = 24;

    /// Create a new Cipher for TCP protocol
    pub fn new(kind: CipherKind, key: &[u8], salt: &[u8]) -> Self {
        let key_material = [key, salt].concat();

        let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
        hasher.update(&key_material);
        let mut hasher_output = hasher.finalize_xof();

        let mut derived_key = vec![0u8; kind.key_len()];
        hasher_output.fill(&mut derived_key);

        let cipher = CipherVariant::new(kind, &derived_key);
        let nlen = cipher.nonce_size();
        debug_assert!(nlen <= Self::N_MAX);
        let nonce = [0u8; Self::N_MAX];

        Self { cipher, nlen, nonce }
    }

    /// Cipher's kind
    #[inline(always)]
    pub fn kind(&self) -> CipherKind {
        self.cipher.kind()
    }

    /// Cipher's category, should always be `Aead2022`
    #[inline(always)]
    pub fn category(&self) -> CipherCategory {
        CipherCategory::Aead2022
    }

    /// Tag size
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

    /// Encrypt a packet
    pub fn encrypt_packet(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = &self.nonce[..self.nlen];
        self.cipher.encrypt(nonce, plaintext_in_ciphertext_out);
        self.increase_nonce();
    }

    /// Decrypt a packet
    pub fn decrypt_packet(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = &self.nonce[..self.nlen];
        let ret = self.cipher.decrypt(nonce, ciphertext_in_plaintext_out);
        self.increase_nonce();
        ret
    }
}
