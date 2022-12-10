use aes_gcm_siv::{
    aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, KeyInit, KeySizeUser},
    Aes128GcmSiv as CryptoAes128GcmSiv,
    Aes256GcmSiv as CryptoAes256GcmSiv,
    Key,
    Nonce,
    Tag,
};

pub struct Aes128GcmSiv(CryptoAes128GcmSiv);

impl Aes128GcmSiv {
    pub fn new(key: &[u8]) -> Aes128GcmSiv {
        let key = Key::<CryptoAes128GcmSiv>::from_slice(key);
        Aes128GcmSiv(CryptoAes128GcmSiv::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoAes128GcmSiv as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoAes128GcmSiv as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoAes128GcmSiv as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_128_GCM_SIV encrypt");
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

pub struct Aes256GcmSiv(CryptoAes256GcmSiv);

impl Aes256GcmSiv {
    pub fn new(key: &[u8]) -> Aes256GcmSiv {
        let key = Key::<CryptoAes256GcmSiv>::from_slice(key);
        Aes256GcmSiv(CryptoAes256GcmSiv::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoAes256GcmSiv as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoAes256GcmSiv as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoAes256GcmSiv as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&mut self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_256_GCM_SIV encrypt");
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
