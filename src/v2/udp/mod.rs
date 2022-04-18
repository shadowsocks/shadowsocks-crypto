//! AEAD 2022 UDP Ciphers

use crate::{CipherCategory, CipherKind};

pub use self::{aes_gcm::Cipher as AesGcmCipher, chacha20_poly1305::Cipher as ChaCha20Poly1305Cipher};

mod aes_gcm;
mod chacha20_poly1305;

enum CipherVariant {
    AesGcm(self::aes_gcm::Cipher),
    ChaCha20Poly1305(self::chacha20_poly1305::Cipher),
}

impl CipherVariant {
    fn new(kind: CipherKind, key: &[u8], nonce: &[u8], session_id: u64) -> CipherVariant {
        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM | CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
                CipherVariant::AesGcm(AesGcmCipher::new(kind, key, session_id))
            }
            CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305 => {
                CipherVariant::ChaCha20Poly1305(ChaCha20Poly1305Cipher::new(key, nonce))
            }
            _ => unreachable!("Cipher {} is not an AEAD 2022 cipher", kind),
        }
    }

    fn encrypt_packet(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        match *self {
            CipherVariant::AesGcm(ref mut c) => c.encrypt_packet(plaintext_in_ciphertext_out),
            CipherVariant::ChaCha20Poly1305(ref mut c) => c.encrypt_packet(plaintext_in_ciphertext_out),
        }
    }

    fn decrypt_packet(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        match *self {
            CipherVariant::AesGcm(ref mut c) => c.decrypt_packet(ciphertext_in_plaintext_out),
            CipherVariant::ChaCha20Poly1305(ref mut c) => c.decrypt_packet(ciphertext_in_plaintext_out),
        }
    }
}

/// AEAD2022 UDP Cipher
pub struct UdpCipher {
    cipher: CipherVariant,
    kind: CipherKind,
}

impl UdpCipher {
    /// Create a new AEAD2022 UDP Cipher
    pub fn new(kind: CipherKind, key: &[u8], nonce: &[u8], session_id: u64) -> UdpCipher {
        UdpCipher {
            cipher: CipherVariant::new(kind, key, nonce, session_id),
            kind,
        }
    }

    /// Cipher's kind
    #[inline(always)]
    pub fn kind(&self) -> CipherKind {
        self.kind
    }

    /// Cipher's category, should always be `Aead2022`
    #[inline(always)]
    pub fn category(&self) -> CipherCategory {
        CipherCategory::Aead2022
    }

    /// Encrypt a UDP packet, including packet header
    pub fn encrypt_packet(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt_packet(plaintext_in_ciphertext_out)
    }

    /// Decrypt a UDP packet, including packet header
    pub fn decrypt_packet(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.cipher.decrypt_packet(ciphertext_in_plaintext_out)
    }
}
