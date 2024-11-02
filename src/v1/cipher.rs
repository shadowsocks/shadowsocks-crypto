use crate::kind::{CipherCategory, CipherKind};

#[cfg(feature = "v1-aead")]
use super::aeadcipher::AeadCipher;
use super::dummy::DummyCipher;
#[cfg(feature = "v1-stream")]
use super::streamcipher::StreamCipher;

#[deprecated(since = "0.5.8", note = "prefer utils::random_iv_or_salt")]
pub use crate::utils::random_iv_or_salt;

/// Key derivation of OpenSSL's [EVP_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
pub fn openssl_bytes_to_key(password: &[u8], key: &mut [u8]) {
    use md5::{Digest, Md5};

    let key_len = key.len();

    let mut last_digest = None;

    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(key_len - offset, digest.len());
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += amt;
        last_digest = Some(digest);
    }
}

/// Unified interface of Ciphers
#[allow(clippy::large_enum_variant)]
pub enum Cipher {
    Dummy(DummyCipher),
    #[cfg(feature = "v1-stream")]
    Stream(StreamCipher),
    #[cfg(feature = "v1-aead")]
    Aead(AeadCipher),
}

macro_rules! cipher_method_forward {
    (ref $self:expr, $method:ident $(, $param:expr),*) => {
        match *$self {
            Cipher::Dummy(ref c) => c.$method($($param),*),
            #[cfg(feature = "v1-stream")]
            Cipher::Stream(ref c) => c.$method($($param),*),
            #[cfg(feature = "v1-aead")]
            Cipher::Aead(ref c) => c.$method($($param),*),
        }
    };

    (mut $self:expr, $method:ident $(, $param:expr),*) => {
        match *$self {
            Cipher::Dummy(ref mut c) => c.$method($($param),*),
            #[cfg(feature = "v1-stream")]
            Cipher::Stream(ref mut c) => c.$method($($param),*),
            #[cfg(feature = "v1-aead")]
            Cipher::Aead(ref mut c) => c.$method($($param),*),
        }
    };
}

impl Cipher {
    /// Create a new Cipher of `kind`
    ///
    /// - Stream Ciphers initialize with IV
    /// - AEAD Ciphers initialize with SALT
    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> Cipher {
        let category = kind.category();

        match category {
            CipherCategory::None => {
                let _ = key;
                let _ = iv_or_salt;

                Cipher::Dummy(DummyCipher::new())
            }
            #[cfg(feature = "v1-stream")]
            CipherCategory::Stream => Cipher::Stream(StreamCipher::new(kind, key, iv_or_salt)),
            #[cfg(feature = "v1-aead")]
            CipherCategory::Aead => {
                use cfg_if::cfg_if;

                const SUBKEY_INFO: &'static [u8] = b"ss-subkey";
                const MAX_KEY_LEN: usize = 64;

                let ikm = key;
                let mut okm = [0u8; MAX_KEY_LEN];

                cfg_if! {
                    if #[cfg(feature = "ring")] {
                        use ring_compat::ring::hkdf::{Salt, HKDF_SHA1_FOR_LEGACY_USE_ONLY, KeyType};

                        struct CryptoKeyType(usize);

                        impl KeyType for CryptoKeyType {
                            #[inline]
                            fn len(&self) -> usize {
                                self.0
                            }
                        }

                        let salt = Salt::new(HKDF_SHA1_FOR_LEGACY_USE_ONLY, iv_or_salt);
                        let prk = salt.extract(ikm);
                        let rokm = prk
                            .expand(&[SUBKEY_INFO], CryptoKeyType(ikm.len()))
                            .expect("HKDF-SHA1-EXPAND");

                        rokm.fill(&mut okm[..ikm.len()]).expect("HKDF-SHA1-FILL");
                    } else {
                        use hkdf::Hkdf;
                        use sha1::Sha1;

                        let hk = Hkdf::<Sha1>::new(Some(iv_or_salt), ikm);
                        hk.expand(SUBKEY_INFO, &mut okm).expect("HKDF-SHA1");
                    }
                }

                let subkey = &okm[..ikm.len()];
                Cipher::Aead(AeadCipher::new(kind, subkey))
            }
            #[allow(unreachable_patterns)]
            _ => unimplemented!("Category {:?} is not v1 protocol", category),
        }
    }

    /// Get the `CipherCategory` of the current cipher
    pub fn category(&self) -> CipherCategory {
        cipher_method_forward!(ref self, category)
    }

    /// Get the `CipherKind` of the current cipher
    pub fn kind(&self) -> CipherKind {
        cipher_method_forward!(ref self, kind)
    }

    /// Get the TAG length of AEAD ciphers
    pub fn tag_len(&self) -> usize {
        cipher_method_forward!(ref self, tag_len)
    }

    /// Encrypt a packet. Encrypted result will be written in `pkt`
    ///
    /// - Stream Ciphers: the size of input and output packets are the same
    /// - AEAD Ciphers: the size of output must be at least `input.len() + TAG_LEN`
    pub fn encrypt_packet(&mut self, pkt: &mut [u8]) {
        cipher_method_forward!(mut self, encrypt, pkt)
    }

    /// Decrypt a packet. Decrypted result will be written in `pkt`
    ///
    /// - Stream Ciphers: the size of input and output packets are the same
    /// - AEAD Ciphers: the size of output is `input.len() - TAG_LEN`
    #[must_use]
    pub fn decrypt_packet(&mut self, pkt: &mut [u8]) -> bool {
        cipher_method_forward!(mut self, decrypt, pkt)
    }
}

#[test]
fn test_cipher_new_none() {
    let key = [2u8; 16];
    let salt = [1u8; 16];
    let kind = CipherKind::NONE;

    let cipher = Cipher::new(kind, &key, &salt);
    assert_eq!(cipher.tag_len(), 0);
}

#[cfg(feature = "v1-aead")]
#[test]
fn test_cipher_new_aead() {
    let key = [2u8; 16];
    let salt = [1u8; 16];
    let kind = CipherKind::AES_128_GCM;

    let cipher = Cipher::new(kind, &key, &salt);
    assert_eq!(cipher.tag_len(), 16);
}

#[cfg(feature = "v1-stream")]
#[test]
fn test_cipher_new_stream() {
    let key = [2u8; 32];
    let iv = [1u8; 12];
    let kind = CipherKind::CHACHA20;

    let cipher = Cipher::new(kind, &key, &iv);
    assert_eq!(cipher.tag_len(), 0);
}

#[test]
fn test_send() {
    fn test<C: Send>() {}
    test::<Cipher>();
}

#[test]
fn test_sync() {
    fn test<C: Sync>() {}
    test::<Cipher>();
}
