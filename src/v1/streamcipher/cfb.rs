// 6.3 The Cipher Feedback Mode, (Page-18)
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
use super::crypto::{
    aes::{Aes128, Aes192, Aes256},
    camellia::{Camellia128, Camellia192, Camellia256},
};

#[derive(Debug, Clone, Copy)]
struct Bits(pub u8);

impl Bits {
    pub fn bit(&self, pos: usize) -> bool {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 & 1 << pos != 0
    }

    pub fn set_bit(&mut self, pos: usize, val: bool) {
        assert!(pos < 8);
        let pos = 8 - pos - 1;
        self.0 ^= (0u8.wrapping_sub(val as u8) ^ self.0) & 1 << pos;
    }

    pub fn bit_xor(&mut self, pos: usize, other: u8) {
        let a = self.bit(pos);
        let b = Bits(other).bit(0);
        if a != b {
            self.set_bit(pos, true);
        } else {
            self.set_bit(pos, false);
        }
    }
}

fn left_shift_1(bytes: &mut [u8], bit: bool) {
    let mut last_bit = if bit { 0b0000_0001 } else { 0b0000_0000 };
    for byte in bytes.iter_mut().rev() {
        let b = (*byte & 0b1000_0000) >> 7;
        *byte <<= 1;
        *byte |= last_bit;
        last_bit = b;
    }
}

macro_rules! impl_block_cipher_with_cfb1_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            last_input_block: [u8; Self::BLOCK_LEN],
        }

        impl $name {
            pub const B: usize = Self::BLOCK_LEN * 8;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize = $cipher::KEY_LEN;
            // The block size, in bits.
            pub const S: usize = 1;

            // The number of bits in a data segment.

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                assert!(Self::BLOCK_LEN <= 16);
                assert!(Self::S <= Self::B);
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(iv.len(), Self::IV_LEN);

                let cipher = $cipher::new(key);

                let mut last_input_block = [0u8; Self::IV_LEN];
                last_input_block.copy_from_slice(iv);

                Self {
                    cipher,
                    last_input_block,
                }
            }

            pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                #[allow(unused_assignments)]
                let mut last_segment = false;

                for i in 0..plaintext_in_ciphertext_out.len() {
                    for bit_pos in 0..8 {
                        let mut keystream = self.last_input_block.clone();
                        self.cipher.encrypt(&mut keystream);

                        let mut byte_bits = Bits(plaintext_in_ciphertext_out[i]);
                        byte_bits.bit_xor(bit_pos, keystream[0]);
                        last_segment = byte_bits.bit(bit_pos);
                        plaintext_in_ciphertext_out[i] = byte_bits.0;

                        // left shift 1 bits
                        left_shift_1(&mut self.last_input_block, last_segment);
                    }
                }
            }

            pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                #[allow(unused_assignments)]
                let mut last_segment = false;

                for i in 0..ciphertext_in_plaintext_out.len() {
                    for bit_pos in 0..8 {
                        let mut keystream = self.last_input_block.clone();
                        self.cipher.encrypt(&mut keystream);

                        let mut byte_bits = Bits(ciphertext_in_plaintext_out[i]);
                        last_segment = byte_bits.bit(bit_pos);
                        byte_bits.bit_xor(bit_pos, keystream[0]);
                        ciphertext_in_plaintext_out[i] = byte_bits.0;

                        // left shift 1 bits
                        left_shift_1(&mut self.last_input_block, last_segment);
                    }
                }
            }
        }
    };
}

macro_rules! impl_block_cipher_with_cfb8_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            last_input_block: [u8; Self::BLOCK_LEN],
        }

        impl $name {
            pub const B: usize = Self::BLOCK_LEN * 8;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize = $cipher::KEY_LEN;
            // The block size, in bits.
            pub const S: usize = 8;

            // The number of bits in a data segment.

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                assert!(Self::S <= Self::B);
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(iv.len(), Self::IV_LEN);

                let cipher = $cipher::new(key);

                let mut last_input_block = [0u8; Self::IV_LEN];
                last_input_block.copy_from_slice(iv);

                Self {
                    cipher,
                    last_input_block,
                }
            }

            pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                #[allow(unused_assignments)]
                let mut last_segment = 0u8;

                for i in 0..plaintext_in_ciphertext_out.len() {
                    let mut keystream = self.last_input_block.clone();
                    self.cipher.encrypt(&mut keystream);

                    plaintext_in_ciphertext_out[i] ^= keystream[0];
                    last_segment = plaintext_in_ciphertext_out[i];

                    // left shift 8 bits
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&self.last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    self.last_input_block = tmp;
                }
            }

            pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                #[allow(unused_assignments)]
                let mut last_segment = 0u8;

                for i in 0..ciphertext_in_plaintext_out.len() {
                    let mut keystream = self.last_input_block.clone();
                    self.cipher.encrypt(&mut keystream);

                    last_segment = ciphertext_in_plaintext_out[i];
                    ciphertext_in_plaintext_out[i] ^= keystream[0];

                    // left shift 8 bits
                    let mut tmp = [0u8; Self::BLOCK_LEN];
                    tmp[0..Self::BLOCK_LEN - 1].copy_from_slice(&self.last_input_block[1..]);
                    tmp[Self::BLOCK_LEN - 1] = last_segment;
                    self.last_input_block = tmp;
                }
            }
        }
    };
}

macro_rules! impl_block_cipher_with_cfb128_mode {
    ($name:tt, $cipher:tt) => {
        #[derive(Clone)]
        pub struct $name {
            cipher: $cipher,
            last_input_block: [u8; Self::BLOCK_LEN],
            keystream: [u8; Self::BLOCK_LEN],
            offset: usize,
        }

        impl $name {
            pub const B: usize = Self::BLOCK_LEN * 8;
            pub const BLOCK_LEN: usize = $cipher::BLOCK_LEN;
            pub const IV_LEN: usize = $cipher::BLOCK_LEN;
            pub const KEY_LEN: usize = $cipher::KEY_LEN;
            // The block size, in bits.
            pub const S: usize = 128;

            // The number of bits in a data segment.

            pub fn new(key: &[u8], iv: &[u8]) -> Self {
                assert!(Self::S <= Self::B);
                assert_eq!(key.len(), Self::KEY_LEN);
                assert_eq!(iv.len(), Self::IV_LEN);

                let cipher = $cipher::new(key);

                let mut last_input_block = [0u8; Self::IV_LEN];
                last_input_block.copy_from_slice(iv);

                let mut keystream = last_input_block.clone();
                cipher.encrypt(&mut keystream);

                Self {
                    cipher,
                    last_input_block,
                    keystream,
                    offset: 0usize,
                }
            }

            pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
                for i in 0..plaintext_in_ciphertext_out.len() {
                    if self.offset == Self::BLOCK_LEN {
                        self.keystream = self.last_input_block.clone();
                        self.cipher.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    plaintext_in_ciphertext_out[i] ^= self.keystream[self.offset];
                    self.last_input_block[self.offset] = plaintext_in_ciphertext_out[i];

                    self.offset += 1;
                }
            }

            pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
                for i in 0..ciphertext_in_plaintext_out.len() {
                    if self.offset == Self::BLOCK_LEN {
                        self.keystream = self.last_input_block.clone();
                        self.cipher.encrypt(&mut self.keystream);

                        self.offset = 0;
                    }

                    self.last_input_block[self.offset] = ciphertext_in_plaintext_out[i];
                    ciphertext_in_plaintext_out[i] ^= self.keystream[self.offset];

                    self.offset += 1;
                }
            }
        }
    };
}

impl_block_cipher_with_cfb1_mode!(Aes128Cfb1, Aes128);
impl_block_cipher_with_cfb1_mode!(Aes192Cfb1, Aes192);
impl_block_cipher_with_cfb1_mode!(Aes256Cfb1, Aes256);
impl_block_cipher_with_cfb1_mode!(Camellia128Cfb1, Camellia128);
impl_block_cipher_with_cfb1_mode!(Camellia192Cfb1, Camellia192);
impl_block_cipher_with_cfb1_mode!(Camellia256Cfb1, Camellia256);

impl_block_cipher_with_cfb8_mode!(Aes128Cfb8, Aes128);
impl_block_cipher_with_cfb8_mode!(Aes192Cfb8, Aes192);
impl_block_cipher_with_cfb8_mode!(Aes256Cfb8, Aes256);
impl_block_cipher_with_cfb8_mode!(Camellia128Cfb8, Camellia128);
impl_block_cipher_with_cfb8_mode!(Camellia192Cfb8, Camellia192);
impl_block_cipher_with_cfb8_mode!(Camellia256Cfb8, Camellia256);

impl_block_cipher_with_cfb128_mode!(Aes128Cfb128, Aes128);
impl_block_cipher_with_cfb128_mode!(Aes192Cfb128, Aes192);
impl_block_cipher_with_cfb128_mode!(Aes256Cfb128, Aes256);
impl_block_cipher_with_cfb128_mode!(Camellia128Cfb128, Camellia128);
impl_block_cipher_with_cfb128_mode!(Camellia192Cfb128, Camellia192);
impl_block_cipher_with_cfb128_mode!(Camellia256Cfb128, Camellia256);

#[test]
fn test_aes128_cfb8() {
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let plaintext = hex::decode(
        "\
6bc1bee22e409f96e93d7e117393172a\
ae2d8a",
    )
    .unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &iv);
    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);

    let mut cipher = Aes128Cfb8::new(&key, &iv);
    let mut cleartext = ciphertext.clone();
    cipher.decryptor_update(&mut cleartext);

    assert_eq!(&cleartext[..], &plaintext[..]);
}

#[test]
fn test_aes128_cfb1_enc() {
    // F.3.1  CFB1-AES128.Encrypt, (Page-36)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb1::new(&key, &iv);
    // 0110_1011_1100_0001
    // 0110_1000_1011_0011
    let plaintext = [0x6b, 0xc1];
    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[0x68, 0xb3]);
}

#[test]
fn test_aes128_cfb1_dec() {
    // F.3.2  CFB1-AES128.Decrypt, (Page-37)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb1::new(&key, &iv);

    let ciphertext = [0x68, 0xb3];
    let mut plaintext = ciphertext.clone();
    cipher.decryptor_update(&mut plaintext);
    assert_eq!(&plaintext[..], &[0x6b, 0xc1]);
}

#[test]
fn test_aes128_cfb8_enc() {
    // F.3.7  CFB8-AES128.Encrypt, (Page-46)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &iv);

    let plaintext = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e];
    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);
    assert_eq!(&ciphertext[..], &[0x3b, 0x79, 0x42, 0x4c, 0x9c,]);
}

#[test]
fn test_aes128_cfb8_dec() {
    // F.3.7  CFB8-AES128.Decrypt, (Page-48)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb8::new(&key, &iv);

    let ciphertext = [0x3b, 0x79, 0x42, 0x4c, 0x9c];
    let mut plaintext = ciphertext.clone();
    cipher.decryptor_update(&mut plaintext);
    assert_eq!(&plaintext[..], &[0x6b, 0xc1, 0xbe, 0xe2, 0x2e]);
}

#[test]
fn test_aes128_cfb128_enc() {
    // F.3.13  CFB128-AES128.Encrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb128::new(&key, &iv);

    let plaintext = hex::decode(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f24",
    )
    .unwrap();

    let mut ciphertext = plaintext.clone();
    cipher.encryptor_update(&mut ciphertext);
    assert_eq!(
        &ciphertext[..],
        &hex::decode(
            "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05"
        )
        .unwrap()[..]
    );
}

#[test]
fn test_aes128_cfb128_dec() {
    // F.3.14  CFB128-AES128.Decrypt, (Page-57)
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let mut cipher = Aes128Cfb128::new(&key, &iv);

    let ciphertext = hex::decode(
        "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05",
    )
    .unwrap();

    let mut plaintext = ciphertext.clone();
    cipher.decryptor_update(&mut plaintext);
    assert_eq!(
        &plaintext[..],
        &hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f24"
        )
        .unwrap()[..]
    );
}
