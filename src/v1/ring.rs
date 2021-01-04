use ring::aead::{
    Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};

pub struct Aes128Gcm {
    cipher: LessSafeKey,
}

impl Aes128Gcm {
    pub const KEY_LEN: usize = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub const A_MAX: usize = 2305843009213693951; // 2 ** 61
    pub const P_MAX: usize = 68719476735; // 2^36 - 31
    pub const C_MAX: usize = 68719476721; // 2^36 - 15
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();

        Self {
            cipher: LessSafeKey::new(unbound_key),
        }
    }

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        let tag = self
            .cipher
            .seal_in_place_separate_tag(nonce, aad, plaintext_in_ciphertext_out)
            .unwrap();
        assert_eq!(tag.as_ref().len(), Self::TAG_LEN);

        tag_out.copy_from_slice(tag.as_ref());
    }

    #[must_use]
    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        match self.cipher.open_in_place(nonce, aad, aead_pkt) {
            Ok(plaintext) => {
                assert_eq!(plaintext.len(), clen);
                true
            }
            Err(_) => false,
        }
    }
}

pub struct Aes256Gcm {
    cipher: LessSafeKey,
}

impl Aes256Gcm {
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub const A_MAX: usize = 2305843009213693951; // 2 ** 61
    pub const P_MAX: usize = 68719476735; // 2^36 - 31
    pub const C_MAX: usize = 68719476721; // 2^36 - 15
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).unwrap();

        Self {
            cipher: LessSafeKey::new(unbound_key),
        }
    }

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        let tag = self
            .cipher
            .seal_in_place_separate_tag(nonce, aad, plaintext_in_ciphertext_out)
            .unwrap();
        assert_eq!(tag.as_ref().len(), Self::TAG_LEN);

        tag_out.copy_from_slice(tag.as_ref());
    }

    #[must_use]
    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        match self.cipher.open_in_place(nonce, aad, aead_pkt) {
            Ok(plaintext) => {
                assert_eq!(plaintext.len(), clen);
                true
            }
            Err(_) => false,
        }
    }
}

pub struct Chacha20Poly1305 {
    cipher: LessSafeKey,
}

impl Chacha20Poly1305 {
    pub const KEY_LEN: usize = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub const A_MAX: usize = usize::MAX; // 2^32 - 1
    pub const P_MAX: usize = 274877906880; // (2^32 - 1) * BLOCK_LEN
    pub const C_MAX: usize = Self::P_MAX + Self::TAG_LEN; // 274,877,906,896
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;

    pub fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), Self::KEY_LEN);

        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap();

        Self {
            cipher: LessSafeKey::new(unbound_key),
        }
    }

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let plen = aead_pkt.len() - Self::TAG_LEN;
        let (plaintext_in_ciphertext_out, tag_out) = aead_pkt.split_at_mut(plen);

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        let tag = self
            .cipher
            .seal_in_place_separate_tag(nonce, aad, plaintext_in_ciphertext_out)
            .unwrap();
        assert_eq!(tag.as_ref().len(), Self::TAG_LEN);

        tag_out.copy_from_slice(tag.as_ref());
    }

    #[must_use]
    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        assert_eq!(nonce.len(), Self::NONCE_LEN);
        assert!(aead_pkt.len() >= Self::TAG_LEN);

        let clen = aead_pkt.len() - Self::TAG_LEN;

        let nonce = Nonce::try_assume_unique_for_key(nonce).unwrap();
        let aad = Aad::from(aad);

        match self.cipher.open_in_place(nonce, aad, aead_pkt) {
            Ok(plaintext) => {
                assert_eq!(plaintext.len(), clen);
                true
            }
            Err(_) => false,
        }
    }
}
