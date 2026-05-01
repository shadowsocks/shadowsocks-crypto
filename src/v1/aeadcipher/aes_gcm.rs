use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "aws-lc")] {
        use aws_lc_rs::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};

        struct AeadKey(LessSafeKey);

        impl AeadKey {
            fn new(algorithm: &'static Algorithm, key: &[u8]) -> AeadKey {
                let unbound = UnboundKey::new(algorithm, key).expect("AEAD key");
                AeadKey(LessSafeKey::new(unbound))
            }

            fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("AEAD nonce");
                let tag_len = self.0.algorithm().tag_len();
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - tag_len);
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, Aad::empty(), plaintext)
                    .expect("AEAD encrypt");
                out_tag.copy_from_slice(tag.as_ref());
            }

            fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_assume_unique_for_key(nonce).expect("AEAD nonce");
                self.0.open_in_place(nonce, Aad::empty(), ciphertext_in_plaintext_out).is_ok()
            }
        }

        macro_rules! aead_cipher {
            ($name:ident, $algorithm:ident) => {
                pub struct $name(AeadKey);

                impl $name {
                    pub fn new(key: &[u8]) -> $name {
                        $name(AeadKey::new(&$algorithm, key))
                    }

                    pub fn key_size() -> usize {
                        $algorithm.key_len()
                    }

                    pub fn nonce_size() -> usize {
                        $algorithm.nonce_len()
                    }

                    pub fn tag_size() -> usize {
                        $algorithm.tag_len()
                    }

                    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                        self.0.encrypt(nonce, plaintext_in_ciphertext_out)
                    }

                    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                        self.0.decrypt(nonce, ciphertext_in_plaintext_out)
                    }
                }
            };
        }

        aead_cipher!(Aes128Gcm, AES_128_GCM);
        aead_cipher!(Aes256Gcm, AES_256_GCM);
    } else if #[cfg(feature = "ring")] {
        use std::convert::{AsMut, AsRef};

        pub use ring_compat::aead::{Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm};
        use ring_compat::{
            aead::{AeadCore, AeadInPlace, Buffer, Error as AeadError, KeySizeUser, KeyInit},
            generic_array::{typenum::Unsigned, GenericArray},
        };

        type Key<B> = GenericArray<u8, <B as KeySizeUser>::KeySize>;
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
            aead::{self, array::typenum::Unsigned, AeadCore, AeadInOut, KeySizeUser, KeyInit},
        };
        use aes_gcm::{Aes128Gcm as CryptoAes128Gcm, Aes256Gcm as CryptoAes256Gcm};

        type Key<A> = aead::Key<A>;
        type Nonce<A> = aead::Nonce<A>;
        type Tag<A> = aead::Tag<A>;

        pub struct Aes128Gcm(Box<CryptoAes128Gcm>);

        impl Aes128Gcm {
            pub fn new(key: &[u8]) -> Aes128Gcm {
                let key = Key::<CryptoAes128Gcm>::try_from(key).expect("AES_128_GCM key");
                Aes128Gcm(Box::new(CryptoAes128Gcm::new(&key)))
            }

            pub fn key_size() -> usize {
                <CryptoAes128Gcm as KeySizeUser>::KeySize::to_usize()
            }

            pub fn nonce_size() -> usize {
                <CryptoAes128Gcm as AeadCore>::NonceSize::to_usize()
            }

            pub fn tag_size() -> usize {
                <CryptoAes128Gcm as AeadCore>::TagSize::to_usize()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::<CryptoAes128Gcm>::try_from(nonce).expect("AES_128_GCM nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_inout_detached(&nonce, &[], plaintext.into())
                    .expect("AES_128_GCM encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::<CryptoAes128Gcm>::try_from(nonce).expect("AES_128_GCM nonce");
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = match Tag::<CryptoAes128Gcm>::try_from(&*in_tag) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
            }
        }

        pub struct Aes256Gcm(Box<CryptoAes256Gcm>);

        impl Aes256Gcm {
            pub fn new(key: &[u8]) -> Aes256Gcm {
                let key = Key::<CryptoAes256Gcm>::try_from(key).expect("AES_256_GCM key");
                Aes256Gcm(Box::new(CryptoAes256Gcm::new(&key)))
            }

            pub fn key_size() -> usize {
                <CryptoAes256Gcm as KeySizeUser>::KeySize::to_usize()
            }

            pub fn nonce_size() -> usize {
                <CryptoAes256Gcm as AeadCore>::NonceSize::to_usize()
            }

            pub fn tag_size() -> usize {
                <CryptoAes256Gcm as AeadCore>::TagSize::to_usize()
            }

            pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
                let nonce = Nonce::<CryptoAes256Gcm>::try_from(nonce).expect("AES_256_GCM nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_inout_detached(&nonce, &[], plaintext.into())
                    .expect("AES_256_GCM encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::<CryptoAes256Gcm>::try_from(nonce).expect("AES_256_GCM nonce");
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = match Tag::<CryptoAes256Gcm>::try_from(&*in_tag) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
            }
        }
    }
}
