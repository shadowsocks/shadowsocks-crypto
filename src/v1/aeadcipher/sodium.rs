//! `libsodium` provided ciphers

use core::convert::TryInto;
use core::ptr;

use libsodium_sys::{
    crypto_aead_xchacha20poly1305_ietf_ABYTES, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
};

use crypto2::mem::Zeroize;
use crypto2::streamcipher::Chacha20;

pub struct XChacha20Poly1305 {
    ek: [u8; Self::KEY_LEN],
}

impl Zeroize for XChacha20Poly1305 {
    fn zeroize(&mut self) {
        self.ek.zeroize()
    }
}

impl Drop for XChacha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl XChacha20Poly1305 {
    pub const KEY_LEN: usize = crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
    pub const NONCE_LEN: usize = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
    pub const TAG_LEN: usize = crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
    pub const N_MIN: usize = Self::NONCE_LEN;
    pub const N_MAX: usize = Self::NONCE_LEN;
    pub const BLOCK_LEN: usize = Chacha20::BLOCK_LEN;

    pub fn new(key: &[u8]) -> Self {
        XChacha20Poly1305 {
            ek: key
                .try_into()
                .expect("key.len() != XChacha20Poly1305::KEY_LEN"),
        }
    }

    pub fn encrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        unsafe {
            let mut clen: libc::c_ulonglong = 0;
            let ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
                aead_pkt.as_mut_ptr() as *mut _,
                &mut clen,
                aead_pkt.as_ptr() as *const _,
                (aead_pkt.len() - Self::TAG_LEN) as libc::c_ulonglong,
                aad.as_ptr() as *const _,
                aad.len() as libc::c_ulonglong,
                ptr::null(),
                nonce.as_ptr() as *const _,
                self.ek.as_ptr() as *const _,
            );
            if ret != 0 || clen != aead_pkt.len() as libc::c_ulonglong {
                panic!(
                    "crypto_aead_xchacha20poly1305_ietf_encrypt ret={} clen={} aead_pkt.len={}",
                    ret,
                    clen,
                    aead_pkt.len(),
                );
            }
        }
    }

    pub fn decrypt_slice(&self, nonce: &[u8], aad: &[u8], aead_pkt: &mut [u8]) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);
        debug_assert!(aead_pkt.len() >= Self::TAG_LEN);

        unsafe {
            let mut mlen: libc::c_ulonglong = 0;
            let ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
                aead_pkt.as_mut_ptr() as *mut _,
                &mut mlen,
                ptr::null_mut(),
                aead_pkt.as_ptr() as *const _,
                aead_pkt.len() as libc::c_ulonglong,
                aad.as_ptr() as *const _,
                aad.len() as libc::c_ulonglong,
                nonce.as_ptr() as *const _,
                self.ek.as_ptr(),
            );

            ret == 0 && mlen == (aead_pkt.len() - Self::TAG_LEN) as libc::c_ulonglong
        }
    }

    #[allow(dead_code)]
    pub fn encrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);
        debug_assert_eq!(tag_out.len(), Self::TAG_LEN);

        unsafe {
            let mut maclen: libc::c_ulonglong = 0;
            let ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                plaintext_in_ciphertext_out.as_mut_ptr() as *mut _,
                tag_out.as_mut_ptr() as *mut _,
                &mut maclen,
                plaintext_in_ciphertext_out.as_ptr() as *const _,
                plaintext_in_ciphertext_out.len() as libc::c_ulonglong,
                aad.as_ptr() as *const _,
                aad.len() as libc::c_ulonglong,
                ptr::null(),
                nonce.as_ptr() as *const _,
                self.ek.as_ptr() as *const _,
            );
            if ret != 0 || maclen != tag_out.len() as libc::c_ulonglong {
                panic!(
                    "crypto_aead_xchacha20poly1305_ietf_encrypt_detached ret={} maclen={} tag_out.len={}",
                    ret, maclen, tag_out.len()
                );
            }
        }
    }

    #[allow(dead_code)]
    pub fn decrypt_slice_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_in_plaintext_out: &mut [u8],
        tag_in: &[u8],
    ) -> bool {
        debug_assert_eq!(nonce.len(), Self::NONCE_LEN);
        debug_assert_eq!(tag_in.len(), Self::TAG_LEN);

        unsafe {
            let ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
                ciphertext_in_plaintext_out.as_mut_ptr() as *mut _,
                ptr::null_mut(),
                ciphertext_in_plaintext_out.as_ptr() as *const _,
                ciphertext_in_plaintext_out.len() as libc::c_ulonglong,
                tag_in.as_ptr() as *const _,
                aad.as_ptr() as *const _,
                aad.len() as libc::c_ulonglong,
                nonce.as_ptr() as *const _,
                self.ek.as_ptr() as *const _,
            );

            ret == 0
        }
    }
}

#[test]
fn test_xchacha20_ietf_poly1305_enc() {
    let key =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("07000000404142434445464748494a4b4c4d4e4f50515253").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    let cipher = XChacha20Poly1305::new(&key);

    let plain_text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    let mut cipher_text = plain_text.to_vec();
    cipher_text.resize(cipher_text.len() + XChacha20Poly1305::TAG_LEN, 0);

    cipher.encrypt_slice(&nonce, &aad, &mut cipher_text);

    let expected_cipher_text = hex::decode("f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002bd1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef10cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e68420").unwrap();
    assert_eq!(cipher_text, expected_cipher_text);

    let mut detached_cipher_text = plain_text.to_vec();
    let mut detached_tag = [0u8; XChacha20Poly1305::TAG_LEN];
    cipher.encrypt_slice_detached(&nonce, &aad, &mut detached_cipher_text, &mut detached_tag);

    let (expected_detached_cipher_text, expected_detached_tag) =
        expected_cipher_text.split_at(plain_text.len());
    assert_eq!(detached_cipher_text, expected_detached_cipher_text);
    assert_eq!(detached_tag, expected_detached_tag);
}

#[test]
fn test_xchacha20_ietf_poly1305_dec() {
    let key =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("07000000404142434445464748494a4b4c4d4e4f50515253").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    let cipher = XChacha20Poly1305::new(&key);

    let expected_plain_text = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let cipher_text = hex::decode("f8ebea4875044066fc162a0604e171feecfb3d20425248563bcfd5a155dcc47bbda70b86e5ab9b55002bd1274c02db35321acd7af8b2e2d25015e136b7679458e9f43243bf719d639badb5feac03f80a19a96ef10cb1d15333a837b90946ba3854ee74da3f2585efc7e1e170e17e15e563e77601f4f85cafa8e5877614e143e68420").unwrap();

    let mut plain_text = cipher_text.clone();
    assert!(cipher.decrypt_slice(&nonce, &aad, &mut plain_text));

    assert_eq!(
        &plain_text[..expected_plain_text.len()],
        expected_plain_text
    );

    let (cipher_text, cipher_tag) = cipher_text.split_at(expected_plain_text.len());
    let mut plain_text = cipher_text.to_vec();
    assert!(cipher.decrypt_slice_detached(&nonce, &aad, &mut plain_text, &cipher_tag));

    assert_eq!(plain_text, expected_plain_text);
}
