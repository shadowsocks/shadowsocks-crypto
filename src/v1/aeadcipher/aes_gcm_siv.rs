use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "aws-lc")] {
        use aws_lc_rs::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM_SIV, AES_256_GCM_SIV};

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

        macro_rules! aead_gcm_siv_cipher {
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

        aead_gcm_siv_cipher!(Aes128GcmSiv, AES_128_GCM_SIV);
        aead_gcm_siv_cipher!(Aes256GcmSiv, AES_256_GCM_SIV);
    } else {
        use aes_gcm_siv::{
            aead::{array::typenum::Unsigned, AeadCore, AeadInOut, KeyInit, KeySizeUser},
            Aes128GcmSiv as CryptoAes128GcmSiv,
            Aes256GcmSiv as CryptoAes256GcmSiv,
            Key,
            Nonce,
            Tag,
        };

        pub struct Aes128GcmSiv(CryptoAes128GcmSiv);

        impl Aes128GcmSiv {
            pub fn new(key: &[u8]) -> Aes128GcmSiv {
                let key = Key::<CryptoAes128GcmSiv>::try_from(key).expect("AES_128_GCM_SIV key");
                Aes128GcmSiv(CryptoAes128GcmSiv::new(&key))
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
                let nonce = Nonce::try_from(nonce).expect("AES_128_GCM_SIV nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_inout_detached(&nonce, &[], plaintext.into())
                    .expect("AES_128_GCM_SIV encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_from(nonce).expect("AES_128_GCM_SIV nonce");
                let (ciphertext, in_tag) =
                    ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
                let in_tag = match Tag::try_from(&*in_tag) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                self.0.decrypt_inout_detached(&nonce, &[], ciphertext.into(), &in_tag).is_ok()
            }
        }

        pub struct Aes256GcmSiv(CryptoAes256GcmSiv);

        impl Aes256GcmSiv {
            pub fn new(key: &[u8]) -> Aes256GcmSiv {
                let key = Key::<CryptoAes256GcmSiv>::try_from(key).expect("AES_256_GCM_SIV key");
                Aes256GcmSiv(CryptoAes256GcmSiv::new(&key))
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
                let nonce = Nonce::try_from(nonce).expect("AES_256_GCM_SIV nonce");
                let (plaintext, out_tag) =
                    plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
                let tag = self
                    .0
                    .encrypt_inout_detached(&nonce, &[], plaintext.into())
                    .expect("AES_256_GCM_SIV encrypt");
                out_tag.copy_from_slice(tag.as_slice())
            }

            pub fn decrypt(&mut self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
                let nonce = Nonce::try_from(nonce).expect("AES_256_GCM_SIV nonce");
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
