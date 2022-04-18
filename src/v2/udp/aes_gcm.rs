//! AEAD 2022 UDP aes-*-gcm Ciphers

use bytes::{BufMut, BytesMut};

use crate::{
    v2::{
        crypto::{Aes128Gcm, Aes256Gcm},
        BLAKE3_KEY_DERIVE_CONTEXT,
    },
    CipherKind,
};

pub enum Cipher {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
}

impl Cipher {
    pub fn new(kind: CipherKind, key: &[u8], session_id: u64) -> Cipher {
        let mut key_material = BytesMut::with_capacity(key.len() + 8);
        key_material.put_slice(key);
        key_material.put_u64(session_id);

        let mut hasher = blake3::Hasher::new_derive_key(BLAKE3_KEY_DERIVE_CONTEXT);
        hasher.update(&key_material);
        let mut hasher_output = hasher.finalize_xof();

        let mut derived_key = vec![0u8; kind.key_len()];
        hasher_output.fill(&mut derived_key);

        match kind {
            CipherKind::AEAD2022_BLAKE3_AES_128_GCM => Cipher::Aes128Gcm(Aes128Gcm::new(&derived_key)),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM => Cipher::Aes256Gcm(Aes256Gcm::new(&derived_key)),
            _ => unreachable!("cipher {} is not an AES2022 AES-GCM cipher", kind),
        }
    }

    pub fn nonce_size() -> usize {
        debug_assert!(Aes128Gcm::nonce_size() == Aes256Gcm::nonce_size());
        Aes128Gcm::nonce_size()
    }

    pub fn encrypt_packet(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        debug_assert!(plaintext_in_ciphertext_out.len() >= 8 + 8 + 16);

        // Use packet's header [4:16] as nonce
        let (packet_header, payload) = plaintext_in_ciphertext_out.split_at_mut(16);
        let nonce = &packet_header[4..];

        match *self {
            Cipher::Aes128Gcm(ref mut c) => c.encrypt(nonce, payload),
            Cipher::Aes256Gcm(ref mut c) => c.encrypt(nonce, payload),
        }
    }

    pub fn decrypt_packet(&mut self, ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        debug_assert!(ciphertext_in_plaintext_out.len() >= 8 + 8 + 16);

        // Use packet's header [4:16] as nonce
        let (packet_header, payload) = ciphertext_in_plaintext_out.split_at_mut(16);
        let nonce = &packet_header[4..];

        match *self {
            Cipher::Aes128Gcm(ref mut c) => c.decrypt(nonce, payload),
            Cipher::Aes256Gcm(ref mut c) => c.decrypt(nonce, payload),
        }
    }
}
