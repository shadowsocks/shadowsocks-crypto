use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ring")] {
        pub use ring_compat::aead::{ChaCha20Poly1305 as CryptoChaCha20Poly1305};
        use ring_compat::{
            aead::{AeadCore, AeadInPlace, NewAead},
            generic_array::{typenum::Unsigned, GenericArray},
        };

        type Key<KeySize> = GenericArray<u8, KeySize>;
        type Nonce<NonceSize> = GenericArray<u8, NonceSize>;
        type Tag<TagSize> = GenericArray<u8, TagSize>;
    } else {
        pub use chacha20poly1305::ChaCha20Poly1305 as CryptoChaCha20Poly1305;
        use chacha20poly1305::{
            aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, NewAead},
            Key,
            Nonce,
            Tag,
        };
    }
}

pub struct ChaCha20Poly1305(CryptoChaCha20Poly1305);

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> ChaCha20Poly1305 {
        let key = Key::from_slice(key);
        ChaCha20Poly1305(CryptoChaCha20Poly1305::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoChaCha20Poly1305 as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoChaCha20Poly1305 as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&mut self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("CHACHA20_POLY1305 encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&mut self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);

        // ring-compat marked decrypt_in_place_detached as unimplemented.
        // But CHACHA20_POLY1305 actually expects tag in the back. So it is safe to use `decrypt_in_place`.
        self.0.decrypt_in_place(nonce, &[], ciphertext_in_plaintext_out).is_ok()
    }
}
