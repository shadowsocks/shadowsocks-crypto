#[cfg(feature = "v1-aead")]
use super::aeadcipher::AeadCipher;
use super::dummy::DummyCipher;
#[cfg(feature = "v1-stream")]
use super::streamcipher::StreamCipher;
use super::CipherCategory;
use super::CipherKind;

use crypto2::hash::Md5;

/// Get available ciphers in string representation
///
/// Commonly used for checking users' configuration input
pub const fn available_ciphers() -> &'static [&'static str] {
    &[
        "plain",
        "none",
        #[cfg(feature = "v1-stream")]
        "table",
        #[cfg(feature = "v1-stream")]
        "rc4-md5",
        // 序列密码
        #[cfg(feature = "v1-stream")]
        "aes-128-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-192-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-256-ctr",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-128-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-192-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb1",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb8",
        #[cfg(feature = "v1-stream")]
        "aes-256-cfb128",
        #[cfg(feature = "v1-stream")]
        "aes-128-ofb",
        #[cfg(feature = "v1-stream")]
        "aes-192-ofb",
        #[cfg(feature = "v1-stream")]
        "aes-256-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-128-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-192-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-256-ctr",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-128-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-192-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb1",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb8",
        #[cfg(feature = "v1-stream")]
        "camellia-256-cfb128",
        #[cfg(feature = "v1-stream")]
        "camellia-128-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-192-ofb",
        #[cfg(feature = "v1-stream")]
        "camellia-256-ofb",
        #[cfg(feature = "v1-stream")]
        "rc4",
        #[cfg(feature = "v1-stream")]
        "chacha20-ietf",
        // AEAD 密码算法
        #[cfg(feature = "v1-aead")]
        "aes-128-gcm",
        #[cfg(feature = "v1-aead")]
        "aes-256-gcm",
        #[cfg(feature = "v1-aead")]
        "chacha20-ietf-poly1305",
        // NOTE: 也许将来会开启的密码算法。
        // "aes-128-ccm", "aes-256-ccm",
        // "aes-128-gcm-siv", "aes-256-gcm-siv",
        // "aes-128-ocb-taglen128", "aes-192-ocb-taglen128", "aes-256-ocb-taglen128",
        // "aes-siv-cmac-256", "aes-siv-cmac-384", "aes-siv-cmac-512",
    ]
}

/// Generate random bytes into `iv_or_salt`
pub fn random_iv_or_salt(iv_or_salt: &mut [u8]) {
    // Gen IV or Gen Salt by KEY-LEN
    if iv_or_salt.is_empty() {
        return ();
    }

    let mut rng = rand::thread_rng();
    loop {
        rand::Rng::fill(&mut rng, iv_or_salt);
        let is_zeros = iv_or_salt.iter().all(|&x| x == 0);
        if !is_zeros {
            break;
        }
    }
}

/// Key derivation of OpenSSL's [EVP_BytesToKey](https://wiki.openssl.org/index.php/Manual:EVP_BytesToKey(3))
pub fn openssl_bytes_to_key(password: &[u8], key: &mut [u8]) {
    let key_len = key.len();

    let mut last_digest: Option<[u8; Md5::DIGEST_LEN]> = None;

    let mut offset = 0usize;
    while offset < key_len {
        let mut m = Md5::new();
        if let Some(digest) = last_digest {
            m.update(&digest);
        }

        m.update(password);

        let digest = m.finalize();

        let amt = std::cmp::min(key_len - offset, Md5::DIGEST_LEN);
        key[offset..offset + amt].copy_from_slice(&digest[..amt]);

        offset += Md5::DIGEST_LEN;
        last_digest = Some(digest);
    }
}

trait CipherInner {
    fn ss_kind(&self) -> CipherKind;
    fn ss_category(&self) -> CipherCategory;
    fn ss_tag_len(&self) -> usize;
    fn ss_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]);
    fn ss_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool;
}

impl CipherInner for DummyCipher {
    fn ss_kind(&self) -> CipherKind {
        CipherKind::NONE
    }
    fn ss_category(&self) -> CipherCategory {
        CipherCategory::None
    }
    fn ss_tag_len(&self) -> usize {
        0
    }
    fn ss_encrypt_slice(&mut self, _plaintext_in_ciphertext_out: &mut [u8]) {}
    fn ss_decrypt_slice(&mut self, _ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        true
    }
}

#[cfg(feature = "v1-stream")]
impl CipherInner for StreamCipher {
    fn ss_kind(&self) -> CipherKind {
        self.kind()
    }
    fn ss_category(&self) -> CipherCategory {
        CipherCategory::Stream
    }
    fn ss_tag_len(&self) -> usize {
        0
    }
    fn ss_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.encrypt(plaintext_in_ciphertext_out)
    }
    fn ss_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.decrypt(ciphertext_in_plaintext_out);
        true
    }
}

#[cfg(feature = "v1-aead")]
impl CipherInner for AeadCipher {
    fn ss_kind(&self) -> CipherKind {
        self.kind()
    }
    fn ss_category(&self) -> CipherCategory {
        CipherCategory::Aead
    }
    fn ss_tag_len(&self) -> usize {
        self.tag_len()
    }
    fn ss_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.encrypt(plaintext_in_ciphertext_out)
    }
    fn ss_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        self.decrypt(ciphertext_in_plaintext_out)
    }
}

/// Unified interface of Ciphers
pub struct Cipher {
    cipher: Box<dyn CipherInner + Send + 'static>,
}

impl Cipher {
    #[cfg(feature = "v1-aead")]
    const MAX_KEY_LEN: usize = 64;
    #[cfg(feature = "v1-aead")]
    const SUBKEY_INFO: &'static [u8] = b"ss-subkey";

    /// Create a new Cipher of `kind`
    ///
    /// - Stream Ciphers initialize with IV
    /// - AEAD Ciphers initialize with SALT
    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> Self {
        let category = kind.category();

        match category {
            CipherCategory::None => {
                let _ = key;
                let _ = iv_or_salt;

                let cipher = Box::new(DummyCipher::new());

                Self { cipher }
            }
            #[cfg(feature = "v1-stream")]
            CipherCategory::Stream => {
                let cipher = Box::new(StreamCipher::new(kind, key, iv_or_salt));

                Self { cipher }
            }
            #[cfg(feature = "v1-aead")]
            CipherCategory::Aead => {
                use crypto2::kdf::HkdfSha1;

                // Gen SubKey
                let ikm = key;
                let mut okm = [0u8; Self::MAX_KEY_LEN];
                HkdfSha1::oneshot(&iv_or_salt, ikm, Self::SUBKEY_INFO, &mut okm[..ikm.len()]);

                let subkey = &okm[..ikm.len()];

                let cipher = Box::new(AeadCipher::new(kind, subkey));

                Self { cipher }
            }
        }
    }

    /// Get the `CipherCategory` of the current cipher
    pub fn category(&self) -> CipherCategory {
        self.cipher.ss_category()
    }

    /// Get the `CipherKind` of the current cipher
    pub fn kind(&self) -> CipherKind {
        self.cipher.ss_kind()
    }

    /// Get the TAG length of AEAD ciphers
    pub fn tag_len(&self) -> usize {
        self.cipher.ss_tag_len()
    }

    /// Encrypt a packet. Encrypted result will be written in `pkt`
    ///
    /// - Stream Ciphers: the size of input and output packets are the same
    /// - AEAD Ciphers: the size of output must be at least `input.len() + TAG_LEN`
    pub fn encrypt_packet(&mut self, pkt: &mut [u8]) {
        self.cipher.ss_encrypt_slice(pkt)
    }

    /// Decrypt a packet. Decrypted result will be written in `pkt`
    ///
    /// - Stream Ciphers: the size of input and output packets are the same
    /// - AEAD Ciphers: the size of output is `input.len() - TAG_LEN`
    #[must_use]
    pub fn decrypt_packet(&mut self, pkt: &mut [u8]) -> bool {
        self.cipher.ss_decrypt_slice(pkt)
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
