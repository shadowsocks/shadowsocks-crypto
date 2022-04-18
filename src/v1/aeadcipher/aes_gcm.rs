use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ring")] {
        use std::convert::{AsMut, AsRef};

        pub use ring_compat::aead::{Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm};
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
        use aes_gcm::{
            aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, NewAead},
            Key,
            Nonce,
            Tag,
        };
        pub use aes_gcm::{Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm};
    }
}

pub struct Aes128Gcm(CryptoAes128Gcm);

impl Aes128Gcm {
    pub fn new(key: &[u8]) -> Aes128Gcm {
        let key = Key::from_slice(key);
        Aes128Gcm(CryptoAes128Gcm::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoAes128Gcm as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoAes128Gcm as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoAes128Gcm as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_128_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);

        cfg_if! {
            if #[cfg(feature = "ring")] {
                // ring-compat marked decrypt_in_place_detached as unimplemented.
                // But AES_128_GCM actually expects tag in the back. So it is safe to use `decrypt_in_place`.

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

pub struct Aes256Gcm(CryptoAes256Gcm);

impl Aes256Gcm {
    pub fn new(key: &[u8]) -> Aes256Gcm {
        let key = Key::from_slice(key);
        Aes256Gcm(CryptoAes256Gcm::new(key))
    }

    pub fn key_size() -> usize {
        <CryptoAes256Gcm as NewAead>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <CryptoAes256Gcm as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <CryptoAes256Gcm as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("AES_256_GCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        cfg_if! {
            if #[cfg(feature = "ring")] {
                // ring-compat marked decrypt_in_place_detached as unimplemented.
                // But AES_256_GCM actually expects tag in the back. So it is safe to use `decrypt_in_place`.

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
