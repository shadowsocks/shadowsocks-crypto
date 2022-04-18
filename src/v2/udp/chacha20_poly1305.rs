//! AEAD 2022 UDP chacha20-poly1305 Ciphers

use crate::v2::crypto::XChaCha20Poly1305;

/// xchacha20-poly1305 nonce size = Cipher::nonce_size()
const NONCE_SIZE: usize = 24;

pub struct Cipher {
    cipher: XChaCha20Poly1305,
    nonce: [u8; NONCE_SIZE],
}

impl Cipher {
    pub fn new(key: &[u8], n: &[u8]) -> Cipher {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(n);

        Cipher {
            cipher: XChaCha20Poly1305::new(key),
            nonce,
        }
    }

    pub fn nonce_size() -> usize {
        XChaCha20Poly1305::nonce_size()
    }

    pub fn encrypt_packet(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt(&self.nonce, plaintext_in_ciphertext_out);
    }

    pub fn decrypt_packet(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.cipher.decrypt(&self.nonce, ciphertext_in_plaintext_out)
    }
}
