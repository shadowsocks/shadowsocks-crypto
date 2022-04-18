use aes::{Aes128, Aes256};
use ccm::{
    aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, NewAead},
    consts::{U12, U16},
    Ccm,
    Nonce,
    Tag,
};

pub struct Aes128Ccm(Ccm<Aes128, U16, U12>);

impl Aes128Ccm {
    pub fn new(key: &[u8]) -> Aes128Ccm {
        Aes128Ccm(Ccm::new_from_slice(key).expect("Aes128Ccm"))
    }

    pub fn key_size() -> usize {
        <Ccm<Aes128, U16, U12> as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <Ccm<Aes128, U16, U12> as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <Ccm<Aes128, U16, U12> as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_128_CCM encrypt");
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

pub struct Aes256Ccm(Ccm<Aes256, U16, U12>);

impl Aes256Ccm {
    pub fn new(key: &[u8]) -> Aes256Ccm {
        Aes256Ccm(Ccm::new_from_slice(key).expect("Aes256Ccm"))
    }

    pub fn key_size() -> usize {
        <Ccm<Aes256, U16, U12> as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <Ccm<Aes256, U16, U12> as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <Ccm<Aes256, U16, U12> as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&mut self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_256_CCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&mut self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
    }
}
