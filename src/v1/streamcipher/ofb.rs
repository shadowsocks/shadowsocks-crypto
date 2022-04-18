// 6.4 The Output Feedback Mode, (Page-20)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
use super::crypto::{
    aes::{Aes128, Aes192, Aes256},
    camellia::{Camellia128, Camellia192, Camellia256},
};

macro_rules! impl_block_cipher_with_ofb_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            last_output_block: [u8; Self::BLOCK_LEN],
            keystream: [u8; Self::BLOCK_LEN],
            offset: usize,
        }

        impl $name {
            // pub const B: usize = Self::BLOCK_LEN * 8;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize = $cipher::KEY_LEN;

            // The block size, in bits.

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(iv.len(), Self::IV_LEN);

                let cipher = $cipher::new(key);

                let mut last_output_block = [0u8; Self::IV_LEN];
                last_output_block.copy_from_slice(iv);

                let mut keystream = last_output_block.clone();
                cipher.encrypt(&mut keystream);

                Self {
                    cipher,
                    last_output_block,
                    keystream,
                    offset: 0usize,
                }
            }

            pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                for i in 0..plaintext_in_ciphertext_out.len() {
                    if self.offset == Self::BLOCK_LEN {
                        self.keystream = self.last_output_block.clone();
                        self.cipher.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    plaintext_in_ciphertext_out[i] ^= self.keystream[self.offset];
                    self.last_output_block[self.offset] = self.keystream[self.offset];

                    self.offset += 1;
                }
            }

            pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                for i in 0..ciphertext_in_plaintext_out.len() {
                    if self.offset == Self::BLOCK_LEN {
                        self.keystream = self.last_output_block.clone();
                        self.cipher.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    self.last_output_block[self.offset] = self.keystream[self.offset];
                    ciphertext_in_plaintext_out[i] ^= self.keystream[self.offset];

                    self.offset += 1;
                }
            }
        }
    };
}

impl_block_cipher_with_ofb_mode!(Aes128Ofb, Aes128);
impl_block_cipher_with_ofb_mode!(Aes192Ofb, Aes192);
impl_block_cipher_with_ofb_mode!(Aes256Ofb, Aes256);
impl_block_cipher_with_ofb_mode!(Camellia128Ofb, Camellia128);
impl_block_cipher_with_ofb_mode!(Camellia192Ofb, Camellia192);
impl_block_cipher_with_ofb_mode!(Camellia256Ofb, Camellia256);

#[test]
fn test_aes128_ofb() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode(
        "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a",
    )
    .unwrap();

    let mut cipher = Aes128Ofb::new(&key, &iv);
    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);

    let mut cipher = Aes128Ofb::new(&key, &iv);
    let mut cleartext = ciphertext.clone();
    cipher.decryptor_update(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_ofb_enc() {
    // F.4.1  OFB-AES128.Encrypt, (Page-59)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let plaintext = hex::decode(
        "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a571e03ac9c9eb76fac45af8e51\
30c81c46a35ce411e5fbc1191a0a52ef\
f69f2445df4f9b17ad2b417be66c3710",
    )
    .unwrap();

    let mut cipher = Aes128Ofb::new(&key, &iv);
    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);

    assert_eq!(
        &ciphertext[..],
        &hex::decode(
            "\
3b3fd92eb72dad20333449f8e83cfb4a\
7789508d16918f03f53c52dac54ed825\
9740051e9c5fecf64344f7a82260edcc\
304c6528f659c77866a510d9c1d6ae5e"
        )
        .unwrap()[..]
    );
}

#[test]
fn test_aes128_ofb_dec() {
    // F.4.2  OFB-AES128.Decrypt, (Page-60)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let ciphertext = hex::decode(
        "\
3b3fd92eb72dad20333449f8e83cfb4a\
7789508d16918f03f53c52dac54ed825\
9740051e9c5fecf64344f7a82260edcc\
304c6528f659c77866a510d9c1d6ae5e",
    )
    .unwrap();

    let mut cipher = Aes128Ofb::new(&key, &iv);
    let mut plaintext = ciphertext.clone();
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
