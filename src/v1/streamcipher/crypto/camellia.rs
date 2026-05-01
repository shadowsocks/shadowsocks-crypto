#![allow(dead_code)]

use camellia::{
    cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockSizeUser, KeyInit, KeySizeUser, typenum::Unsigned},
    Camellia128 as CryptoCamellia128,
    Camellia192 as CryptoCamellia192,
    Camellia256 as CryptoCamellia256,
};

#[derive(Debug, Clone)]
pub struct Camellia128(CryptoCamellia128);

impl Camellia128 {
    pub const BLOCK_LEN: usize = <CryptoCamellia128 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = <CryptoCamellia128 as KeySizeUser>::KeySize::USIZE;

    pub fn new(key: &[u8]) -> Camellia128 {
        Camellia128(CryptoCamellia128::new_from_slice(key).expect("Camellia128"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia128>>::try_from(block).expect("block size");
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia128>>::try_from(block).expect("block size");
        self.0.decrypt_block(block);
    }
}

#[derive(Debug, Clone)]
pub struct Camellia192(CryptoCamellia192);

impl Camellia192 {
    pub const BLOCK_LEN: usize = <CryptoCamellia192 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = <CryptoCamellia192 as KeySizeUser>::KeySize::USIZE;

    pub fn new(key: &[u8]) -> Camellia192 {
        Camellia192(CryptoCamellia192::new_from_slice(key).expect("Camellia192"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia192>>::try_from(block).expect("block size");
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia192>>::try_from(block).expect("block size");
        self.0.decrypt_block(block);
    }
}

#[derive(Debug, Clone)]
pub struct Camellia256(CryptoCamellia256);

impl Camellia256 {
    pub const BLOCK_LEN: usize = <CryptoCamellia256 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = <CryptoCamellia256 as KeySizeUser>::KeySize::USIZE;

    pub fn new(key: &[u8]) -> Camellia256 {
        Camellia256(CryptoCamellia256::new_from_slice(key).expect("Camellia256"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia256>>::try_from(block).expect("block size");
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = <&mut Block<CryptoCamellia256>>::try_from(block).expect("block size");
        self.0.decrypt_block(block);
    }
}
