//! AEAD 2022 UDP chacha8-poly1305 Ciphers

use crate::v2::crypto::XChaCha8Poly1305;

pub struct Cipher {
    cipher: XChaCha8Poly1305,
}

impl Cipher {
    pub fn new(key: &[u8]) -> Cipher {
        debug_assert_eq!(key.len(), XChaCha8Poly1305::key_size());
        Cipher {
            cipher: XChaCha8Poly1305::new(key),
        }
    }

    pub fn nonce_size() -> usize {
        XChaCha8Poly1305::nonce_size()
    }

    pub fn encrypt_packet(&self, salt: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt(salt, plaintext_in_ciphertext_out);
    }

    pub fn decrypt_packet(&self, salt: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.cipher.decrypt(salt, ciphertext_in_plaintext_out)
    }
}
