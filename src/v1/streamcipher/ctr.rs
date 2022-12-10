// 6.5 The Counter Mode, (Page-22)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

use aes::{
    cipher::{Iv, IvSizeUser, Key, KeyIvInit, StreamCipher, Unsigned},
    Aes128 as CryptoAes128,
    Aes192 as CryptoAes192,
    Aes256 as CryptoAes256,
};
use ctr::Ctr64BE;

use super::crypto::{
    aes::{Aes128, Aes192, Aes256},
    camellia::{Camellia128, Camellia192, Camellia256},
};

type CryptoAes128Ctr = Ctr64BE<CryptoAes128>;
type CryptoAes192Ctr = Ctr64BE<CryptoAes192>;
type CryptoAes256Ctr = Ctr64BE<CryptoAes256>;

pub struct Aes128Ctr(CryptoAes128Ctr);

impl Aes128Ctr {
    pub const IV_LEN: usize = <CryptoAes128Ctr as IvSizeUser>::IvSize::USIZE;
    pub const KEY_LEN: usize = Aes128::KEY_LEN;

    pub fn new(key: &[u8], iv: &[u8]) -> Aes128Ctr {
        let key = Key::<CryptoAes128Ctr>::from_slice(key);
        let iv = Iv::<CryptoAes128Ctr>::from_slice(iv);
        let ctr = CryptoAes128Ctr::new(key, iv);
        Aes128Ctr(ctr)
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.0.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.0.apply_keystream(ciphertext_in_plaintext_out);
    }
}

pub struct Aes192Ctr(CryptoAes192Ctr);

impl Aes192Ctr {
    pub const IV_LEN: usize = <CryptoAes192Ctr as IvSizeUser>::IvSize::USIZE;
    pub const KEY_LEN: usize = Aes192::KEY_LEN;

    pub fn new(key: &[u8], iv: &[u8]) -> Aes192Ctr {
        let key = Key::<CryptoAes192Ctr>::from_slice(key);
        let iv = Iv::<CryptoAes192Ctr>::from_slice(iv);
        let ctr = CryptoAes192Ctr::new(key, iv);
        Aes192Ctr(ctr)
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.0.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.0.apply_keystream(ciphertext_in_plaintext_out);
    }
}

pub struct Aes256Ctr(CryptoAes256Ctr);

impl Aes256Ctr {
    pub const IV_LEN: usize = <CryptoAes256Ctr as IvSizeUser>::IvSize::USIZE;
    pub const KEY_LEN: usize = Aes256::KEY_LEN;

    pub fn new(key: &[u8], iv: &[u8]) -> Aes256Ctr {
        let key = Key::<CryptoAes256Ctr>::from_slice(key);
        let iv = Iv::<CryptoAes256Ctr>::from_slice(iv);
        let ctr = CryptoAes256Ctr::new(key, iv);
        Aes256Ctr(ctr)
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.0.apply_keystream(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.0.apply_keystream(ciphertext_in_plaintext_out);
    }
}

macro_rules! impl_block_cipher_with_ctr_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            counter_block: [u8; Self::BLOCK_LEN],
            keystream: [u8; Self::BLOCK_LEN],
            offset: usize,
        }

        impl $name {
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize = $cipher::KEY_LEN;

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                assert_eq!(Self::BLOCK_LEN, 16);
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(iv.len(), Self::IV_LEN);

                let cipher = $cipher::new(key);

                let mut counter_block = [0u8; Self::IV_LEN];
                counter_block.copy_from_slice(iv);

                let mut keystream = counter_block.clone();
                cipher.encrypt(&mut keystream);
                Self::ctr128(&mut counter_block);

                Self {
                    cipher,
                    counter_block,
                    keystream,
                    offset: 0usize,
                }
            }

            // NOTE: OpenSSL 的 CTR 模式把整个 Block 当作计数器。也就是 u128。
            #[inline]
            fn ctr128(counter_block: &mut [u8; Self::BLOCK_LEN]) {
                let octets = u128::from_be_bytes(*counter_block).wrapping_add(1).to_be_bytes();
                counter_block.copy_from_slice(&octets)
            }

            #[inline]
            fn process(&mut self, plaintext_or_ciphertext: &mut [u8]) {
                for i in 0..plaintext_or_ciphertext.len() {
                    if self.offset == Self::BLOCK_LEN {
                        self.keystream = self.counter_block.clone();
                        self.cipher.encrypt(&mut self.keystream);
                        Self::ctr128(&mut self.counter_block);

                        self.offset = 0;
                    }

                    plaintext_or_ciphertext[i] ^= self.keystream[self.offset];
                    self.offset += 1;
                }
            }

            pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                self.process(plaintext_in_ciphertext_out)
            }

            pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                self.process(ciphertext_in_plaintext_out)
            }
        }
    };
}

impl_block_cipher_with_ctr_mode!(Camellia128Ctr, Camellia128);
impl_block_cipher_with_ctr_mode!(Camellia192Ctr, Camellia192);
impl_block_cipher_with_ctr_mode!(Camellia256Ctr, Camellia256);

#[test]
fn test_aes128_ctr() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode(
        "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a",
    )
    .unwrap();

    let mut ciphertext = plaintext.clone();
    let mut cipher = Aes128Ctr::new(&key, &iv);
    cipher.encryptor_update(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let mut cipher = Aes128Ctr::new(&key, &iv);
    cipher.decryptor_update(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

// F.5 CTR Example Vectors, (Page-62)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
#[test]
fn test_aes128_ctr_enc() {
    // F.5.1  CTR-AES128.Encrypt, (Page-62)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let plaintext = hex::decode(
        "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710",
    )
    .unwrap();

    let mut ciphertext = plaintext.clone();
    let mut cipher = Aes128Ctr::new(&key, &iv);
    cipher.encryptor_update(&mut ciphertext);

    assert_eq!(
        &ciphertext[..],
        &hex::decode(
            "\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee"
        )
        .unwrap()[..]
    );
}

#[test]
fn test_aes128_ctr_dec() {
    // F.5.2  CTR-AES128.Decrypt, (Page-63)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let ciphertext = hex::decode(
        "\
874d6191b620e3261bef6864990db6ce\
9806f66b7970fdff8617187bb9fffdff\
5ae4df3edbd5d35e5b4f09020db03eab\
1e031dda2fbe03d1792170a0f3009cee",
    )
    .unwrap();

    let mut plaintext = ciphertext.clone();
    let mut cipher = Aes128Ctr::new(&key, &iv);
    cipher.decryptor_update(&mut plaintext);

    assert_eq!(
        &plaintext[..],
        &hex::decode(
            "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710"
        )
        .unwrap()[..]
    );
}
