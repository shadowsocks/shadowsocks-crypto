use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "aws-lc")] {
        use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

        pub struct ChaCha20Poly1305(LessSafeKey);

        impl ChaCha20Poly1305 {
            pub fn new(key: &[u8]) -> ChaCha20Poly1305 {
                let unbound = UnboundKey::new(&CHACHA20_POLY1305, key).expect("CHACHA20_POLY1305 key");
                ChaCha20Poly1305(LessSafeKey::new(unbound))
            }

            pub fn key_size() -> usize {
                CHACHA20_POLY1305.key_len()
            }

            pub fn nonce_size() -> usize {
                CHACHA20_POLY1305.nonce_len()
            }

            pub fn tag_size() -> usize {
                CHACHA20_POLY1305.tag_len()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("CHACHA20_POLY1305 nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, Aad::empty(), plaintext)
                    .expect("CHACHA20_POLY1305 encrypt");
                out_tag.copy_from_slice(tag.as_ref());
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("CHACHA20_POLY1305 nonce");
                self.0.open_in_place(nonce, Aad::empty(), ciphertext_in_plaintext_out).is_ok()
            }
        }
    } else if #[cfg(feature = "ring")] {
        use std::convert::{AsMut, AsRef};

        pub use ring_compat::aead::{ChaCha20Poly1305 as CryptoChaCha20Poly1305};
        use ring_compat::{
            aead::{AeadCore, AeadInPlace, Buffer, Error as AeadError, KeySizeUser, KeyInit},
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
        use chacha20poly1305::ChaCha20Poly1305 as CryptoChaCha20Poly1305;
        use chacha20poly1305::{
            aead::{array::typenum::Unsigned, AeadCore, AeadInOut, KeySizeUser, KeyInit},
            Key,
            Nonce,
            Tag,
        };

        pub struct ChaCha20Poly1305(CryptoChaCha20Poly1305);

        impl ChaCha20Poly1305 {
            pub fn new(key: &[u8]) -> ChaCha20Poly1305 {
                let key = Key::try_from(key).expect("CHACHA20_POLY1305 key");
                ChaCha20Poly1305(CryptoChaCha20Poly1305::new(&key))
            }

            pub fn key_size() -> usize {
                <CryptoChaCha20Poly1305 as KeySizeUser>::KeySize::to_usize()
            }

            pub fn nonce_size() -> usize {
                <CryptoChaCha20Poly1305 as AeadCore>::NonceSize::to_usize()
            }

            pub fn tag_size() -> usize {
                <CryptoChaCha20Poly1305 as AeadCore>::TagSize::to_usize()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::try_from(nonce).expect("CHACHA20_POLY1305 nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_inout_detached(&nonce, &[], plaintext.into())
                    .expect("CHACHA20_POLY1305 encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_from(nonce).expect("CHACHA20_POLY1305 nonce");
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = match Tag::try_from(&*in_tag) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
            }
        }
    }
}
