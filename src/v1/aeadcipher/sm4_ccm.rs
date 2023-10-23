//! SM4_CCM
//!
//! https://datatracker.ietf.org/doc/html/rfc8998

use ccm::{
    aead::{generic_array::typenum::Unsigned, AeadCore, AeadInPlace, KeyInit, KeySizeUser},
    consts::{U12, U16},
    Ccm,
    Nonce,
    Tag,
};
use sm4::Sm4;

pub struct Sm4Ccm(Ccm<Sm4, U16, U12>);

impl Sm4Ccm {
    pub fn new(key: &[u8]) -> Sm4Ccm {
        Sm4Ccm(Ccm::new_from_slice(key).expect("Sm4Ccm"))
    }

    pub fn key_size() -> usize {
        <Ccm<Sm4, U16, U12> as KeySizeUser>::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        <Ccm<Sm4, U16, U12> as AeadCore>::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        <Ccm<Sm4, U16, U12> as AeadCore>::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let nonce = Nonce::from_slice(nonce);
        let (plaintext, out_tag) =
            plaintext_in_ciphertext_out.split_at_mut(plaintext_in_ciphertext_out.len() - Self::tag_size());
        let tag = self
            .0
            .encrypt_in_place_detached(nonce, &[], plaintext)
            .expect("SM4_CCM encrypt");
        out_tag.copy_from_slice(tag.as_slice())
    }

    pub fn decrypt(&self, nonce: &[u8], ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        let nonce = Nonce::from_slice(nonce);
        let (ciphertext, in_tag) =
            ciphertext_in_plaintext_out.split_at_mut(ciphertext_in_plaintext_out.len() - Self::tag_size());
        let in_tag = Tag::from_slice(in_tag);
        self.0.decrypt_in_place_detached(nonce, &[], ciphertext, in_tag).is_ok()
    }
}

#[cfg(test)]
mod test {
    use ccm::{
        aead::{Aead, KeyInit, Payload},
        consts::{U12, U16},
        Ccm,
    };
    use sm4::Sm4;

    #[test]
    fn test_sm4_ccm() {
        let iv = hex::decode("00001234567800000000ABCD").unwrap();
        let key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();
        let plain_text = hex::decode("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA").unwrap();
        let aad = hex::decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2").unwrap();
        let mut cipher_text = hex::decode("48AF93501FA62ADBCD414CCE6034D895DDA1BF8F132F042098661572E7483094FD12E518CE062C98ACEE28D95DF4416BED31A2F04476C18BB40C84A74B97DC5B").unwrap();
        let mut tag = hex::decode("16842D4FA186F56AB33256971FA110F4").unwrap();
        cipher_text.append(&mut tag); // postfix tag

        let nonce = super::Nonce::from_slice(&iv);

        let cipher = Ccm::<Sm4, U16, U12>::new_from_slice(&key).unwrap();
        let plain_text_payload = Payload {
            msg: &plain_text,
            aad: &aad,
        };
        let result = cipher.encrypt(nonce, plain_text_payload).unwrap();

        assert_eq!(result, cipher_text);
    }
}
