//! SM4-GCM

use aead::{AeadCore, AeadInPlace, Key, KeyInit, KeySizeUser};
use sm4::cipher::Unsigned;

use super::sm4_gcm_cipher::{Nonce, Sm4Gcm as CryptoSm4Gcm, Tag};

pub struct Sm4Gcm(CryptoSm4Gcm);

impl Sm4Gcm {
    pub fn new(key: &[u8]) -> Sm4Gcm {
        let key = Key::<CryptoSm4Gcm>::from_slice(key);
        Sm4Gcm(CryptoSm4Gcm::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoSm4Gcm as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoSm4Gcm as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoSm4Gcm as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("SM4_GCM encrypt");
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
