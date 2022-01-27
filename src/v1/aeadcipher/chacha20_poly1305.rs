use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ring")] {
        use std::convert::{AsMut, AsRef};

        pub use ring_compat::aead::{ChaCha20Poly1305 as CryptoChaCha20Poly1305};
        use ring_compat::{
            aead::{AeadCore, AeadInPlace, Buffer, Error as AeadError, NewAead},
            generic_array::{typenum::Unsigned, GenericArray},
        };

        type Key<KeySize> = GenericArray<u8, KeySize>;
        type Nonce<NonceSize> = GenericArray<u8, NonceSize>;

        struct SliceBuffer<'a>(&'a mut [u8]);

        impl AsRef<[u8]> for SliceBuffer<'_> {
            fn as_ref(&self) -> &[u8] {
                self.0
            }
        }

        impl AsMut<[u8]> for SliceBuffer<'_> {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0
            }
        }

        impl Buffer for SliceBuffer<'_> {
            fn extend_from_slice(&mut self, _other: &[u8]) -> Result<(), AeadError> {
                unimplemented!("not used in decrypt_in_place")
            }

            fn truncate(&mut self, _len: usize) {}
        }
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

        cfg_if! {
            if #[cfg(feature = "ring")] {
                // ring-compat marked decrypt_in_place_detached as unimplemented.
                // But CHACHA20_POLY1305 actually expects tag in the back. So it is safe to use `decrypt_in_place`.

                let mut buffer = SliceBuffer(ciphertext_in_plaintext_out);
                self.0.decrypt_in_place(nonce, &[], &mut buffer).is_ok()
            } else {
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = Tag::from_slice(in_tag);
                self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
            }
        }
    }
}
