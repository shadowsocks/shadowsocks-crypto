#![allow(dead_code)]

use super::CipherKind;

mod cfb;
mod chacha20;
mod ctr;
mod ofb;
mod rc4;
mod rc4_md5;
mod table;

pub use self::cfb::*;
pub use self::chacha20::*;
pub use self::ctr::*;
pub use self::ofb::*;
pub use self::rc4::*;
pub use self::rc4_md5::*;
pub use self::table::*;

trait StreamCipherInner {
    fn sc_kind(&self) -> CipherKind;
    fn sc_key_len(&self) -> usize;
    fn sc_iv_len(&self) -> usize;
    fn sc_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]);
    fn sc_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]);
}

macro_rules! impl_cipher {
    ($name:tt, $kind:tt) => {
        impl StreamCipherInner for $name {
            fn sc_kind(&self) -> CipherKind {
                CipherKind::$kind
            }
            fn sc_key_len(&self) -> usize {
                self.sc_kind().key_len()
            }
            fn sc_iv_len(&self) -> usize {
                self.sc_kind().iv_len()
            }
            fn sc_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                self.encryptor_update(plaintext_in_ciphertext_out);
            }

            fn sc_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                self.decryptor_update(ciphertext_in_plaintext_out);
            }
        }
    };
}

impl_cipher!(Table, SS_TABLE);
impl_cipher!(Rc4Md5, SS_RC4_MD5);

impl_cipher!(Aes128Ctr, AES_128_CTR);
impl_cipher!(Aes192Ctr, AES_192_CTR);
impl_cipher!(Aes256Ctr, AES_256_CTR);

impl_cipher!(Aes128Cfb1, AES_128_CFB1);
impl_cipher!(Aes128Cfb8, AES_128_CFB8);
impl_cipher!(Aes128Cfb128, AES_128_CFB128);

impl_cipher!(Aes192Cfb1, AES_192_CFB1);
impl_cipher!(Aes192Cfb8, AES_192_CFB8);
impl_cipher!(Aes192Cfb128, AES_192_CFB128);

impl_cipher!(Aes256Cfb1, AES_256_CFB1);
impl_cipher!(Aes256Cfb8, AES_256_CFB8);
impl_cipher!(Aes256Cfb128, AES_256_CFB128);

impl_cipher!(Aes128Ofb, AES_128_OFB);
impl_cipher!(Aes192Ofb, AES_192_OFB);
impl_cipher!(Aes256Ofb, AES_256_OFB);

impl_cipher!(Camellia128Ctr, CAMELLIA_128_CTR);
impl_cipher!(Camellia192Ctr, CAMELLIA_192_CTR);
impl_cipher!(Camellia256Ctr, CAMELLIA_256_CTR);

impl_cipher!(Camellia128Cfb1, CAMELLIA_128_CFB1);
impl_cipher!(Camellia128Cfb8, CAMELLIA_128_CFB8);
impl_cipher!(Camellia128Cfb128, CAMELLIA_128_CFB128);

impl_cipher!(Camellia192Cfb1, CAMELLIA_192_CFB1);
impl_cipher!(Camellia192Cfb8, CAMELLIA_192_CFB8);
impl_cipher!(Camellia192Cfb128, CAMELLIA_192_CFB128);

impl_cipher!(Camellia256Cfb1, CAMELLIA_256_CFB1);
impl_cipher!(Camellia256Cfb8, CAMELLIA_256_CFB8);
impl_cipher!(Camellia256Cfb128, CAMELLIA_256_CFB128);

impl_cipher!(Camellia128Ofb, CAMELLIA_128_OFB);
impl_cipher!(Camellia192Ofb, CAMELLIA_192_OFB);
impl_cipher!(Camellia256Ofb, CAMELLIA_256_OFB);

impl_cipher!(Rc4, RC4);
impl_cipher!(Chacha20, CHACHA20);

pub struct StreamCipher {
    cipher: Box<dyn StreamCipherInner + Send + Sync + 'static>,
}

impl StreamCipher {
    pub fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Self {
        use self::CipherKind::*;

        let cipher: Box<dyn StreamCipherInner + Send + Sync + 'static> = match kind {
            SS_TABLE => Box::new(Table::new(key, iv)),
            SS_RC4_MD5 => Box::new(Rc4Md5::new(key, iv)),
            AES_128_CTR => Box::new(Aes128Ctr::new(key, iv)),
            AES_192_CTR => Box::new(Aes192Ctr::new(key, iv)),
            AES_256_CTR => Box::new(Aes256Ctr::new(key, iv)),
            AES_128_CFB1 => Box::new(Aes128Cfb1::new(key, iv)),
            AES_128_CFB8 => Box::new(Aes128Cfb8::new(key, iv)),
            AES_128_CFB128 => Box::new(Aes128Cfb128::new(key, iv)),
            AES_192_CFB1 => Box::new(Aes192Cfb1::new(key, iv)),
            AES_192_CFB8 => Box::new(Aes192Cfb8::new(key, iv)),
            AES_192_CFB128 => Box::new(Aes192Cfb128::new(key, iv)),
            AES_256_CFB1 => Box::new(Aes256Cfb1::new(key, iv)),
            AES_256_CFB8 => Box::new(Aes256Cfb8::new(key, iv)),
            AES_256_CFB128 => Box::new(Aes256Cfb128::new(key, iv)),
            AES_128_OFB => Box::new(Aes128Ofb::new(key, iv)),
            AES_192_OFB => Box::new(Aes192Ofb::new(key, iv)),
            AES_256_OFB => Box::new(Aes256Ofb::new(key, iv)),
            CAMELLIA_128_CTR => Box::new(Camellia128Ctr::new(key, iv)),
            CAMELLIA_192_CTR => Box::new(Camellia192Ctr::new(key, iv)),
            CAMELLIA_256_CTR => Box::new(Camellia256Ctr::new(key, iv)),
            CAMELLIA_128_CFB1 => Box::new(Camellia128Cfb1::new(key, iv)),
            CAMELLIA_128_CFB8 => Box::new(Camellia128Cfb8::new(key, iv)),
            CAMELLIA_128_CFB128 => Box::new(Camellia128Cfb128::new(key, iv)),
            CAMELLIA_192_CFB1 => Box::new(Camellia192Cfb1::new(key, iv)),
            CAMELLIA_192_CFB8 => Box::new(Camellia192Cfb8::new(key, iv)),
            CAMELLIA_192_CFB128 => Box::new(Camellia192Cfb128::new(key, iv)),
            CAMELLIA_256_CFB1 => Box::new(Camellia256Cfb1::new(key, iv)),
            CAMELLIA_256_CFB8 => Box::new(Camellia256Cfb8::new(key, iv)),
            CAMELLIA_256_CFB128 => Box::new(Camellia256Cfb128::new(key, iv)),
            CAMELLIA_128_OFB => Box::new(Camellia128Ofb::new(key, iv)),
            CAMELLIA_192_OFB => Box::new(Camellia192Ofb::new(key, iv)),
            CAMELLIA_256_OFB => Box::new(Camellia256Ofb::new(key, iv)),
            RC4 => Box::new(Rc4::new(key, iv)),
            CHACHA20 => Box::new(Chacha20::new(key, iv)),
            _ => panic!("only support Stream ciphers"),
        };

        Self { cipher }
    }

    pub fn kind(&self) -> CipherKind {
        self.cipher.sc_kind()
    }

    pub fn key_len(&self) -> usize {
        self.cipher.sc_key_len()
    }

    pub fn iv_len(&self) -> usize {
        self.cipher.sc_iv_len()
    }

    pub fn encrypt(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.cipher.sc_encrypt_slice(plaintext_in_ciphertext_out);
    }

    pub fn decrypt(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.cipher.sc_decrypt_slice(ciphertext_in_plaintext_out);
    }
}
