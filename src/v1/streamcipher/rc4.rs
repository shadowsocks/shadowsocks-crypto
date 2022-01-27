//! RC4 Source Code
//! <http://cypherpunks.venona.com/archive/1994/09/msg00304.html>
//!
//! <https://en.wikipedia.org/wiki/RC4>

use crate::v1::streamcipher::crypto::rc4::Rc4 as CryptoRc4;

#[derive(Clone)]
pub struct Rc4 {
    cipher: CryptoRc4,
}

impl Rc4 {
    pub fn new(key: &[u8], _nonce: &[u8]) -> Self {
        let cipher = CryptoRc4::new(key);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt_slice(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.decrypt_slice(ciphertext_in_plaintext_out);
    }

    pub const fn key_size() -> usize {
        // Defined by Shadowsocks' specification.
        16
    }

    pub const fn nonce_size() -> usize {
        // Defined by Shadowsocks' specification.
        0
    }
}
