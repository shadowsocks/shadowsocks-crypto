//! RC4 Source Code
//! http://cypherpunks.venona.com/archive/1994/09/msg00304.html
//!
//! https://en.wikipedia.org/wiki/RC4

#[derive(Clone)]
pub struct Rc4 {
    cipher: crypto2::streamcipher::Rc4,
}

impl Rc4 {
    pub const MIN_KEY_LEN: usize = crypto2::streamcipher::Rc4::MIN_KEY_LEN;
    pub const MAX_KEY_LEN: usize = crypto2::streamcipher::Rc4::MAX_KEY_LEN;

    pub fn new(key: &[u8], _nonce: &[u8]) -> Self {
        let cipher = crypto2::streamcipher::Rc4::new(key);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt_slice(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.decrypt_slice(ciphertext_in_plaintext_out);
    }
}
