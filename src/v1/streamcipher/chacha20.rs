use crypto2::mem::Zeroize;

/// ChaCha20 for IETF Protocols
///
/// https://tools.ietf.org/html/rfc8439
#[derive(Clone)]
pub struct Chacha20 {
    cipher: crypto2::streamcipher::Chacha20,
    nonce: [u8; Self::NONCE_LEN],
    len: u64,
}

impl Zeroize for Chacha20 {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.nonce.zeroize();
        self.len.zeroize()
    }
}

impl Drop for Chacha20 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Chacha20 {
    pub const KEY_LEN: usize = crypto2::streamcipher::Chacha20::KEY_LEN;
    pub const BLOCK_LEN: usize = crypto2::streamcipher::Chacha20::BLOCK_LEN;
    pub const NONCE_LEN: usize = crypto2::streamcipher::Chacha20::NONCE_LEN;

    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);
        assert_eq!(nonce.len(), Self::NONCE_LEN);

        let cipher = crypto2::streamcipher::Chacha20::new(key);

        let mut nonce_copy = [0u8; Self::NONCE_LEN];
        nonce_copy.copy_from_slice(nonce);

        Self {
            cipher,
            nonce: nonce_copy,
            len: 0u64,
        }
    }

    #[inline]
    fn in_place(&mut self, m: &mut [u8]) {
        let mlen = m.len();

        // padding
        let pad_len = (self.len % Self::BLOCK_LEN as u64) as usize;

        let mut buf = m.to_vec();
        for _ in 0..pad_len {
            buf.insert(0, 0);
        }

        let block_counter = if cfg!(any(
            target_pointer_width = "32",
            target_pointer_width = "64"
        )) {
            self.len / Self::BLOCK_LEN as u64
        } else {
            unreachable!()
        };
        assert!(block_counter <= u32::MAX as u64);
        let block_counter = block_counter as u32;

        self.cipher
            .encrypt_slice(block_counter, &self.nonce, &mut buf);

        m.copy_from_slice(&buf[pad_len..]);

        if cfg!(any(
            target_pointer_width = "32",
            target_pointer_width = "64"
        )) {
            self.len += mlen as u64;
        } else {
            unreachable!()
        }
    }

    pub fn encryptor_update(&mut self, plaintext_in_ciphertext_out: &mut [u8]) {
        self.in_place(plaintext_in_ciphertext_out);
    }

    pub fn decryptor_update(&mut self, ciphertext_in_plaintext_out: &mut [u8]) {
        self.in_place(ciphertext_in_plaintext_out);
    }
}
