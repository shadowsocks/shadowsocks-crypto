use md5::{Digest, Md5};

use crate::v1::streamcipher::crypto::rc4::Rc4 as CryptoRc4;

/// Rc4Md5 Cipher
#[derive(Clone)]
pub struct Rc4Md5 {
    cipher: CryptoRc4,
}

impl core::fmt::Debug for Rc4Md5 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Rc4Md5").finish()
    }
}

impl Rc4Md5 {
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        assert_eq!(salt.len(), Self::nonce_size());

        let mut m = Md5::new();
        m.update(key);
        m.update(salt);

        let key = m.finalize();

        let cipher = CryptoRc4::new(&key);

        Self { cipher }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.encrypt_slice(plaintext_in_ciphertext_out)
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.decrypt_slice(ciphertext_in_plaintext_out)
    }

    pub const fn key_size() -> usize {
        // Defined by Shadowsocks' specification.
        16
    }

    pub const fn nonce_size() -> usize {
        // Defined by Shadowsocks' specification.
        16
    }
}

#[test]
fn test_rc4_md5() {
    let key: &[u8] = b"key";
    let nonce: &[u8] = b"abcdefg123abcdef";
    let plaintext: &[u8] = b"abcd1234";

    let mut ciphertext = plaintext.to_vec();
    let mut cipher = Rc4Md5::new(key, nonce);
    cipher.encryptor_update(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let mut cipher = Rc4Md5::new(key, nonce);
    cipher.decryptor_update(&mut cleartext);

    assert_eq!(&cleartext[..], plaintext);
}
