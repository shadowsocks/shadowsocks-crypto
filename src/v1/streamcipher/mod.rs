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

trait StreamCipherExt {
    fn sc_kind(&self) -> CipherKind;
    fn sc_key_len(&self) -> usize;
    fn sc_iv_len(&self) -> usize;
    fn sc_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]);
    fn sc_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]);
}

macro_rules! impl_cipher {
    ($name:tt, $kind:tt) => {
        impl StreamCipherExt for $name {
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

macro_rules! stream_cipher_variant {
    ($($name:ident @ $kind:ident,)+) => {
        enum StreamCipherInner {
            $($name($name),)+
        }

        impl StreamCipherInner {
            fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Self {
                match kind {
                    $(CipherKind::$kind => StreamCipherInner::$name($name::new(key, iv)),)+
                    _ => unreachable!("unrecognized stream cipher kind {:?}", kind),
                }
            }
        }

        impl StreamCipherExt for StreamCipherInner {
            fn sc_kind(&self) -> CipherKind {
                match *self {
                    $(StreamCipherInner::$name(ref c) => c.sc_kind(),)+
                }
            }

            fn sc_key_len(&self) -> usize {
                match *self {
                    $(StreamCipherInner::$name(ref c) => c.sc_key_len(),)+
                }
            }

            fn sc_iv_len(&self) -> usize {
                match *self {
                    $(StreamCipherInner::$name(ref c) => c.sc_iv_len(),)+
                }
            }

            fn sc_encrypt_slice(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                match *self {
                    $(StreamCipherInner::$name(ref mut c) => c.sc_encrypt_slice(plaintext_in_ciphertext_out),)+
                }
            }

            fn sc_decrypt_slice(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                match *self {
                    $(StreamCipherInner::$name(ref mut c) => c.sc_decrypt_slice(ciphertext_in_plaintext_out),)+
                }
            }
        }
    };
}

stream_cipher_variant! {
    Table @ SS_TABLE,
    Rc4Md5 @ SS_RC4_MD5,

    Aes128Ctr @ AES_128_CTR,
    Aes192Ctr @ AES_192_CTR,
    Aes256Ctr @ AES_256_CTR,

    Aes128Cfb1 @ AES_128_CFB1,
    Aes128Cfb8 @ AES_128_CFB8,
    Aes128Cfb128 @ AES_128_CFB128,

    Aes192Cfb1 @ AES_192_CFB1,
    Aes192Cfb8 @ AES_192_CFB8,
    Aes192Cfb128 @ AES_192_CFB128,

    Aes256Cfb1 @ AES_256_CFB1,
    Aes256Cfb8 @ AES_256_CFB8,
    Aes256Cfb128 @ AES_256_CFB128,

    Aes128Ofb @ AES_128_OFB,
    Aes192Ofb @ AES_192_OFB,
    Aes256Ofb @ AES_256_OFB,

    Camellia128Ctr @ CAMELLIA_128_CTR,
    Camellia192Ctr @ CAMELLIA_192_CTR,
    Camellia256Ctr @ CAMELLIA_256_CTR,

    Camellia128Cfb1 @ CAMELLIA_128_CFB1,
    Camellia128Cfb8 @ CAMELLIA_128_CFB8,
    Camellia128Cfb128 @ CAMELLIA_128_CFB128,

    Camellia192Cfb1 @ CAMELLIA_192_CFB1,
    Camellia192Cfb8 @ CAMELLIA_192_CFB8,
    Camellia192Cfb128 @ CAMELLIA_192_CFB128,

    Camellia256Cfb1 @ CAMELLIA_256_CFB1,
    Camellia256Cfb8 @ CAMELLIA_256_CFB8,
    Camellia256Cfb128 @ CAMELLIA_256_CFB128,

    Camellia128Ofb @ CAMELLIA_128_OFB,
    Camellia192Ofb @ CAMELLIA_192_OFB,
    Camellia256Ofb @ CAMELLIA_256_OFB,

    Rc4 @ RC4,

    Chacha20 @ CHACHA20,
}

pub struct StreamCipher {
    cipher: StreamCipherInner,
}

impl StreamCipher {
    pub fn new(kind: CipherKind, key: &[u8], iv: &[u8]) -> Self {
        let cipher = StreamCipherInner::new(kind, key, iv);
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
