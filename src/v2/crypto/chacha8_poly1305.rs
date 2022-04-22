pub use chacha20poly1305::ChaCha8Poly1305 as CryptoChaCha8Poly1305;
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, NewAead},
    Key,
    Nonce,
    Tag,
};

pub struct ChaCha8Poly1305(CryptoChaCha8Poly1305);

impl ChaCha8Poly1305 {
    pub fn new(key: &[u8]) -> ChaCha8Poly1305 {
        let key = Key::from_slice(key);
        ChaCha8Poly1305(CryptoChaCha8Poly1305::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoChaCha8Poly1305 as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoChaCha8Poly1305 as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoChaCha8Poly1305 as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("CHACHA8_POLY1305 encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
    }
}
