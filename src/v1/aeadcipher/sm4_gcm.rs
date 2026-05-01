//! SM4-GCM

use aead::{array::typenum::Unsigned, AeadCore, AeadInOut, Key, KeyInit, KeySizeUser};

use super::sm4_gcm_cipher::{Nonce, Sm4Gcm as CryptoSm4Gcm, Tag};

pub struct Sm4Gcm(CryptoSm4Gcm);

impl Sm4Gcm {
    pub fn new(key: &[u8]) -> Sm4Gcm {
        let key = Key::<CryptoSm4Gcm>::try_from(key).expect("SM4_GCM key");
        Sm4Gcm(CryptoSm4Gcm::new(&key))
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
        let nonce = Nonce::try_from(nonce).expect("SM4_GCM nonce");
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_inout_detached(&nonce, &[], plaintext.into())
            .expect("SM4_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::try_from(nonce).expect("SM4_GCM nonce");
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = match Tag::try_from(&*in_tag) {
            Ok(t) => t,
            Err(_) => return false,
        };
        self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
    }
}
