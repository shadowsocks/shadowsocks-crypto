#![allow(dead_code)]

use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit, Unsigned},
    Aes128 as CryptoAes128,
    Aes192 as CryptoAes192,
    Aes256 as CryptoAes256,
    Block,
};

#[derive(Debug, Clone)]
pub struct Aes128(CryptoAes128);

impl Aes128 {
    pub const BLOCK_LEN: usize = <CryptoAes128 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = 16;

    pub fn new(key: &[u8]) -> Aes128 {
        Aes128(CryptoAes128::new_from_slice(key).expect("Aes128"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.decrypt_block(block);
    }
}

#[derive(Debug, Clone)]
pub struct Aes192(CryptoAes192);

impl Aes192 {
    pub const BLOCK_LEN: usize = <CryptoAes192 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = 24;

    pub fn new(key: &[u8]) -> Aes192 {
        Aes192(CryptoAes192::new_from_slice(key).expect("Aes192"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.decrypt_block(block);
    }
}

#[derive(Debug, Clone)]
pub struct Aes256(CryptoAes256);

impl Aes256 {
    pub const BLOCK_LEN: usize = <CryptoAes256 as BlockSizeUser>::BlockSize::USIZE;
    pub const KEY_LEN: usize = 32;

    pub fn new(key: &[u8]) -> Aes256 {
        Aes256(CryptoAes256::new_from_slice(key).expect("Aes256"))
    }

    pub fn encrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.encrypt_block(block);
    }

    pub fn decrypt(&self, block: &mut [u8]) {
        let block = Block::from_mut_slice(block);
        self.0.decrypt_block(block);
    }
}
