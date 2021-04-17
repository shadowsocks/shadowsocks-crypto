use crypto2::mac::Poly1305;
use crypto2::mem::constant_time_eq;

mod xchacha20;
pub use self::xchacha20::XChacha20;

/// XChaCha20Poly1305
#[derive(Clone)]
pub struct XChacha20Poly1305 {
    chacha20: XChacha20,
}

impl core::fmt::Debug for XChacha20Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("XChacha20Poly1305").finish()
    }
}

impl XChacha20Poly1305 {
    pub const KEY_LEN: usize = XChacha20::KEY_LEN; // 32 bytes
    pub const BLOCK_LEN: usize = XChacha20::BLOCK_LEN; // 64 bytes
    pub const NONCE_LEN: usize = XChacha20::NONCE_LEN; // 24 bytes
    pub const TAG_LEN: usize = Poly1305::TAG_LEN; // 16 bytes

    #[cfg(target_pointer_width = "64")]
    pub const A_MAX: usize = u64::MAX as usize; // 2^64 - 1
    #[cfg(target_pointer_width = "32")]
    pub const A_MAX: usize = usize::MAX; // 2^32 - 1

    #[cfg(target_pointer_width = "64")]
    pub const P_MAX: usize = 274877906880; // (2^32 - 1) * BLOCK_LEN
    #[cfg(target_pointer_width = "32")]
    pub const P_MAX: usize = usize::MAX;   // 2^32 - 1

    #[allow(dead_code)]
    #[cfg(target_pointer_width = "64")]
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    #[allow(dead_code)]
    #[cfg(target_pointer_width = "32")]
    pub const C_MAX: usize = Self::P_MAX - Self::TAG_LEN; // 4294967279
    
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(Self::KEY_LEN, Poly1305::KEY_LEN);
        assert_eq!(key.len(), Self::KEY_LEN);

        let chacha20 = XChacha20::new(key);

        Self { chacha20 }
    }

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        self.encrypt_slice_detached(nonce, aad, plaintext_in_ciphertext_out, tag_out)
    }

    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;
        let (ciphertext_in_plaintext_out, tag_in) = aead_pkt.split_at_mut(clen);

        self.decrypt_slice_detached(nonce, aad, ciphertext_in_plaintext_out, &tag_in)
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let plen = plaintext_in_ciphertext_out.len();
        let tlen = tag_out.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(plen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, &nonce, &mut keystream);

            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };

        // NOTE: 初始 BlockCounter = 1;
        self.chacha20
            .encrypt_slice(1, &nonce, plaintext_in_ciphertext_out);

        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(&plaintext_in_ciphertext_out);

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(plen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        tag_out.copy_from_slice(&tag[..Self::TAG_LEN]);
    }

    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8],
    ) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);

        let alen = aad.len();
        let clen = ciphertext_in_plaintext_out.len();
        let tlen = tag_in.len();

        debug_assert!(alen <= Self::A_MAX);
        debug_assert!(clen <= Self::P_MAX);
        debug_assert!(tlen == Self::TAG_LEN);

        let mut poly1305 = {
            let mut keystream = [0u8; Self::BLOCK_LEN];
            // NOTE: 初始 BlockCounter = 0;
            self.chacha20.encrypt_slice(0, &nonce, &mut keystream);

            let mut poly1305_key = [0u8; Poly1305::KEY_LEN];
            poly1305_key.copy_from_slice(&keystream[..Poly1305::KEY_LEN][..]);

            Poly1305::new(&poly1305_key[..])
        };

        // NOTE: Poly1305 会自动 对齐数据。
        poly1305.update(aad);
        poly1305.update(&ciphertext_in_plaintext_out);

        let mut len_block = [0u8; 16];
        len_block[0..8].copy_from_slice(&(alen as u64).to_le_bytes());
        len_block[8..16].copy_from_slice(&(clen as u64).to_le_bytes());

        poly1305.update(&len_block);

        let tag = poly1305.finalize();

        // Verify
        let is_match = constant_time_eq(tag_in, &tag[..Self::TAG_LEN]);

        if is_match {
            // NOTE: 初始 BlockCounter = 1;
            self.chacha20
                .decrypt_slice(1, &nonce, ciphertext_in_plaintext_out);
        }

        is_match
    }
}

#[test]
fn test_xchacha20_poly1305() {
    // Additional Test Vectors
    //   Example and Test Vector for AEAD_XCHACHA20_POLY1305
    //
    // https://github.com/bikeshedders/xchacha-rfc/blob/master/xchacha.md#additional-test-vectors
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let nonce = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];

    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    let plen = plaintext.len();
    let clen = plen + XChacha20Poly1305::TAG_LEN;

    let mut ciphertext = plaintext.to_vec();
    ciphertext.resize(clen, 0u8);

    let cipher = XChacha20Poly1305::new(&key);
    cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);

    assert_eq!(
        &ciphertext,
        &[
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0,
            0xe9, 0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c,
            0x21, 0x39, 0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3,
            0xa8, 0x2f, 0x4e, 0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16,
            0xcb, 0x96, 0xb7, 0x2e, 0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5,
            0xd9, 0x45, 0xb1, 0x1b, 0x69, 0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b,
            0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2, 0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9,
            0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76, 0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13,
            0xb5, 0x2e, // TAG
            0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7, 0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a,
            0xcf, 0x49,
        ]
    );
}
