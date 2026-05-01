pub use chacha20poly1305::XChaCha20Poly1305 as CryptoXChaCha20Poly1305;
use chacha20poly1305::{
    aead::{array::typenum::Unsigned, AeadCore, AeadInOut, KeyInit, KeySizeUser},
    Key,
    Tag,
    XNonce,
};

pub struct XChaCha20Poly1305(CryptoXChaCha20Poly1305);

impl XChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> XChaCha20Poly1305 {
        let key = Key::try_from(key).expect("XCHACHA20_POLY1305 key");
        XChaCha20Poly1305(CryptoXChaCha20Poly1305::new(&key))
    }

    pub fn key_size() -> usize {
        <CryptoXChaCha20Poly1305 as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoXChaCha20Poly1305 as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoXChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = XNonce::try_from(nonce).expect("XCHACHA20_POLY1305 nonce");
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_inout_detached(&nonce, &[], plaintext.into())
            .expect("XCHACHA20_POLY1305 encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = XNonce::try_from(nonce).expect("XCHACHA20_POLY1305 nonce");
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = match Tag::try_from(&*in_tag) {
            Ok(t) => t,
            Err(_) => return false,
        };
        self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
    }
}
