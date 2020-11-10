use super::dummy::DummyCipher;
use super::streamcipher::StreamCipher;
use super::aeadcipher::AeadCipher;
use super::CipherKind;
use super::CipherCategory;

use crypto2::hash::Md5;
use crypto2::kdf::HkdfSha1;


pub const fn available_ciphers() -> &'static [&'static str] {
    &[
        "plain", "none", "table", "rc4-md5",

        // 序列密码
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-cfb", "aes-128-cfb1", "aes-128-cfb8", "aes-128-cfb128",
        "aes-192-cfb", "aes-192-cfb1", "aes-192-cfb8", "aes-192-cfb128",
        "aes-256-cfb", "aes-256-cfb1", "aes-256-cfb8", "aes-256-cfb128",
        "aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
        "camellia-128-ctr", "camellia-192-ctr", "camellia-256-ctr",
        "camellia-128-cfb", "camellia-128-cfb1", "camellia-128-cfb8", "camellia-128-cfb128",
        "camellia-192-cfb", "camellia-192-cfb1", "camellia-192-cfb8", "camellia-192-cfb128",
        "camellia-256-cfb", "camellia-256-cfb1", "camellia-256-cfb8", "camellia-256-cfb128",
        "camellia-128-ofb", "camellia-192-ofb", "camellia-256-ofb",
        "rc4", "chacha20-ietf",

        // AEAD 密码算法
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", 
        // NOTE: 也许将来会开启的密码算法。
        // "aes-128-ccm", "aes-256-ccm", 
        // "aes-128-gcm-siv", "aes-256-gcm-siv",
        // "aes-128-ocb-taglen128", "aes-192-ocb-taglen128", "aes-256-ocb-taglen128", 
        // "aes-siv-cmac-256", "aes-siv-cmac-384", "aes-siv-cmac-512", 
    ]
}

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
    fn ss_encrypt_slice(&mut self, _plaintext_in_ciphertext_out: &mut [u8]) {
        
    }
    fn ss_decrypt_slice(&mut self, _ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        true
    }
}

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

pub struct Cipher {
    cipher: Box<dyn CipherInner + Send + 'static>,
}

impl Cipher {
    const MAX_KEY_LEN: usize = 64;
    const SUBKEY_INFO: &'static [u8] = b"ss-subkey";


    pub fn new(kind: CipherKind, key: &[u8], iv_or_salt: &[u8]) -> Self {
        let category = kind.category();

        match category {
            CipherCategory::None => {
                let cipher = Box::new(DummyCipher::new());

                Self { cipher }
            },
            CipherCategory::Stream => {
                let cipher = Box::new(StreamCipher::new(kind, key, iv_or_salt));

                Self { cipher }
            },
            CipherCategory::Aead => {
                // Gen SubKey
                let ikm = key;
                let mut okm = [0u8; Self::MAX_KEY_LEN];
                HkdfSha1::oneshot(&iv_or_salt, ikm, Self::SUBKEY_INFO, &mut okm[..ikm.len()]);

                let subkey = &okm[..ikm.len()];

                let cipher = Box::new(AeadCipher::new(kind, subkey));

                Self { cipher }
            },
        }
    }

    pub fn category(&self) -> CipherCategory {
        self.cipher.ss_category()
    }

    pub fn kind(&self) -> CipherKind {
        self.cipher.ss_kind()
    }

    pub fn tag_len(&self) -> usize {
        self.cipher.ss_tag_len()
    }

    pub fn encrypt_packet(&mut self, pkt: &mut [u8]) {
        self.cipher.ss_encrypt_slice(pkt)
    }

    #[must_use]
    pub fn decrypt_packet(&mut self, pkt: &mut [u8]) -> bool {
        self.cipher.ss_decrypt_slice(pkt)
    }
}

#[test]
fn test_cipher_new() {
    let key  = [2u8; 16];
    let salt = [1u8; 16];
    let kind = CipherKind::AES_128_GCM;
    
    let mut cipher = Cipher::new(kind, &key, &salt);
    assert_eq!(cipher.tag_len(), 16);

    
    let key  = [2u8; 32];
    let iv   = [1u8; 12];
    let kind = CipherKind::CHACHA20;
    
    let mut cipher = Cipher::new(kind, &key, &iv);
    assert_eq!(cipher.tag_len(), 0);
}
