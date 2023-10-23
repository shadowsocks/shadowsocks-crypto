//! SM4_GCM
//!
//! https://datatracker.ietf.org/doc/html/rfc8998

use aead::{
    consts::{U0, U12, U16},
    generic_array::GenericArray,
    AeadCore,
    AeadInPlace,
    Key,
    KeyInit,
    KeySizeUser,
};
use ghash::{universal_hash::UniversalHash, GHash};
use sm4::{
    cipher::{BlockEncrypt, InnerIvInit, StreamCipherCore, Unsigned},
    Sm4,
};

/// Maximum length of associated data.
pub const A_MAX: u64 = 1 << 36;

/// Maximum length of plaintext.
pub const P_MAX: u64 = 1 << 36;

/// Maximum length of ciphertext.
pub const C_MAX: u64 = (1 << 36) + 16;

/// SM4-GCM nonces.
pub type Nonce = GenericArray<u8, U12>;

/// SM4-GCM tags.
pub type Tag = GenericArray<u8, U16>;

/// SM4 block.
type Block = GenericArray<u8, U16>;

/// Counter mode with a 32-bit big endian counter.
type Ctr32BE<'a> = ctr::CtrCore<&'a Sm4, ctr::flavors::Ctr32BE>;

pub struct Sm4Gcm {
    cipher: Sm4,
    ghash: GHash,
}

impl KeySizeUser for Sm4Gcm {
    type KeySize = <Sm4 as KeySizeUser>::KeySize;
}

impl KeyInit for Sm4Gcm {
    fn new(key: &Key<Self>) -> Self {
        Sm4::new(key).into()
    }
}

impl From<Sm4> for Sm4Gcm {
    fn from(cipher: Sm4) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        // ghash_key.zeroize();

        Self { cipher, ghash }
    }
}

impl AeadCore for Sm4Gcm {
    type CiphertextOverhead = U0;
    type NonceSize = U12;
    type TagSize = U16;
}

impl AeadInPlace for Sm4Gcm {
    fn encrypt_in_place_detached(&self, nonce: &Nonce, associated_data: &[u8], buffer: &mut [u8]) -> aead::Result<Tag> {
        if buffer.len() as u64 > P_MAX || associated_data.len() as u64 > A_MAX {
            return Err(aead::Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        ctr.apply_keystream_partial(buffer.into());

        let full_tag = self.compute_tag(mask, associated_data, buffer);
        Ok(Tag::clone_from_slice(&full_tag[..Self::TagSize::to_usize()]))
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        if buffer.len() as u64 > C_MAX || associated_data.len() as u64 > A_MAX {
            return Err(aead::Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        // TODO(tarcieri): interleave encryption with GHASH
        // See: <https://github.com/RustCrypto/AEADs/issues/74>
        let expected_tag = self.compute_tag(mask, associated_data, buffer);

        use subtle::ConstantTimeEq;
        if expected_tag[..<Self as AeadCore>::TagSize::to_usize()]
            .ct_eq(tag)
            .into()
        {
            ctr.apply_keystream_partial(buffer.into());
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}

impl Sm4Gcm {
    /// Initialize counter mode.
    ///
    /// See algorithm described in Section 7.2 of NIST SP800-38D:
    /// <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
    ///
    /// > Define a block, J0, as follows:
    /// > If len(IV)=96, then J0 = IV || 0{31} || 1.
    /// > If len(IV) ≠ 96, then let s = 128 ⎡len(IV)/128⎤-len(IV), and
    /// >     J0=GHASH(IV||0s+64||[len(IV)]64).
    fn init_ctr(&self, nonce: &Nonce) -> (Ctr32BE, Block) {
        let j0 = if <Self as AeadCore>::NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);

            let mut block = ghash::Block::default();
            let nonce_bits = (<Self as AeadCore>::NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        let mut ctr = Ctr32BE::inner_iv_init(&self.cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);
        (ctr, tag_mask)
    }

    /// Authenticate the given plaintext and associated data using GHASH.
    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&[block]);

        let mut tag = ghash.finalize();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }

        tag
    }
}

#[cfg(test)]
mod test {
    use aead::{Aead, KeyInit, Payload};

    #[test]
    fn test_sm4_gcm() {
        let iv = hex::decode("00001234567800000000ABCD").unwrap();
        let key = hex::decode("0123456789ABCDEFFEDCBA9876543210").unwrap();
        let plain_text = hex::decode("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA").unwrap();
        let aad = hex::decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2").unwrap();
        let mut cipher_text = hex::decode("17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D").unwrap();
        let mut tag = hex::decode("83DE3541E4C2B58177E065A9BF7B62EC").unwrap();
        cipher_text.append(&mut tag); // postfix tag

        let nonce = super::Nonce::from_slice(&iv);

        let cipher = super::Sm4Gcm::new_from_slice(&key).unwrap();
        let plain_text_payload = Payload {
            msg: &plain_text,
            aad: &aad,
        };
        let result = cipher.encrypt(nonce, plain_text_payload).unwrap();

        assert_eq!(result, cipher_text);
    }
}
