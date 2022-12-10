use chacha20::{
    cipher::{IvSizeUser, KeyIvInit, KeySizeUser, StreamCipher, Unsigned},
    ChaCha20,
    Key,
    Nonce,
};

/// ChaCha20 for IETF Protocols
///
/// https://tools.ietf.org/html/rfc8439
pub struct Chacha20 {
    cipher: ChaCha20,
}

impl Chacha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let key = Key::from_slice(key);
        let nonce = Nonce::from_slice(nonce);
        let cipher = ChaCha20::new(key, nonce);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.apply_keystream(ciphertext_in_plaintext_out);
    }

    pub fn key_size() -> usize {
        <ChaCha20 as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <ChaCha20 as IvSizeUser>::IvSize::to_usize()
    }
}
