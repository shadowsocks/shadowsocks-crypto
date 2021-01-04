//! Cipher Kind

#[cfg(feature = "v1-aead")]
use super::aeadcipher::{
    Aes128Ccm, Aes128Gcm, Aes128GcmSiv, Aes128OcbTag128, Aes192OcbTag128, Aes256Ccm, Aes256Gcm,
    Aes256GcmSiv, Aes256OcbTag128, AesSivCmac256, AesSivCmac384, AesSivCmac512, Chacha20Poly1305,
};
#[cfg(feature = "v1-stream")]
use super::streamcipher::{
    Aes128Cfb1,
    Aes128Cfb128,
    Aes128Cfb8,
    Aes128Ctr,
    Aes128Ofb,
    Aes192Cfb1,
    Aes192Cfb128,
    Aes192Cfb8,
    Aes192Ctr,
    Aes192Ofb,
    Aes256Cfb1,
    Aes256Cfb128,

    Aes256Cfb8,
    Aes256Ctr,
    Aes256Ofb,
    Camellia128Cfb1,
    Camellia128Cfb128,
    Camellia128Cfb8,
    Camellia128Ctr,
    Camellia128Ofb,
    Camellia192Cfb1,
    Camellia192Cfb128,
    Camellia192Cfb8,
    Camellia192Ctr,
    Camellia192Ofb,
    Camellia256Cfb1,
    Camellia256Cfb128,

    Camellia256Cfb8,
    Camellia256Ctr,
    Camellia256Ofb,
    Chacha20,
    // Rc4, Rc4Md5, Table,
};

/// Category of ciphers
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CipherCategory {
    /// No encryption
    None,
    /// Stream ciphers is used for OLD ShadowSocks protocol, which uses stream ciphers to encrypt data payloads
    #[cfg(feature = "v1-stream")]
    Stream,
    /// AEAD ciphers is used in modern ShadowSocks protocol, which sends data in separate packets
    #[cfg(feature = "v1-aead")]
    Aead,
}

/// ShadowSocks cipher type
#[allow(non_camel_case_types)]
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CipherKind {
    NONE,

    #[cfg(feature = "v1-stream")]
    SS_TABLE,
    #[cfg(feature = "v1-stream")]
    SS_RC4_MD5,

    #[cfg(feature = "v1-stream")]
    AES_128_CTR,
    #[cfg(feature = "v1-stream")]
    AES_192_CTR,
    #[cfg(feature = "v1-stream")]
    AES_256_CTR,

    #[cfg(feature = "v1-stream")]
    AES_128_CFB1,
    #[cfg(feature = "v1-stream")]
    AES_128_CFB8,
    #[cfg(feature = "v1-stream")]
    AES_128_CFB128,
    #[cfg(feature = "v1-stream")]
    AES_192_CFB1,
    #[cfg(feature = "v1-stream")]
    AES_192_CFB8,
    #[cfg(feature = "v1-stream")]
    AES_192_CFB128,
    #[cfg(feature = "v1-stream")]
    AES_256_CFB1,
    #[cfg(feature = "v1-stream")]
    AES_256_CFB8,
    #[cfg(feature = "v1-stream")]
    AES_256_CFB128,

    #[cfg(feature = "v1-stream")]
    AES_128_OFB,
    #[cfg(feature = "v1-stream")]
    AES_192_OFB,
    #[cfg(feature = "v1-stream")]
    AES_256_OFB,

    #[cfg(feature = "v1-stream")]
    CAMELLIA_128_CTR,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_192_CTR,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_256_CTR,

    #[cfg(feature = "v1-stream")]
    CAMELLIA_128_CFB1,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_128_CFB8,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_128_CFB128,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_192_CFB1,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_192_CFB8,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_192_CFB128,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_256_CFB1,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_256_CFB8,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_256_CFB128,

    #[cfg(feature = "v1-stream")]
    CAMELLIA_128_OFB,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_192_OFB,
    #[cfg(feature = "v1-stream")]
    CAMELLIA_256_OFB,

    #[cfg(feature = "v1-stream")]
    RC4,
    // NOTE: IETF 版本
    #[cfg(feature = "v1-stream")]
    CHACHA20,

    // AEAD Cipher
    #[cfg(feature = "v1-aead")]
    AES_128_CCM, // AEAD_AES_128_CCM
    #[cfg(feature = "v1-aead")]
    AES_256_CCM, // AEAD_AES_256_CCM
    #[cfg(feature = "v1-aead")]
    AES_128_OCB_TAGLEN128, // AEAD_AES_128_OCB_TAGLEN128
    #[cfg(feature = "v1-aead")]
    AES_192_OCB_TAGLEN128, // AEAD_AES_192_OCB_TAGLEN128
    #[cfg(feature = "v1-aead")]
    AES_256_OCB_TAGLEN128, // AEAD_AES_256_OCB_TAGLEN128
    #[cfg(feature = "v1-aead")]
    AES_128_GCM, // AEAD_AES_128_GCM
    #[cfg(feature = "v1-aead")]
    AES_256_GCM, // AEAD_AES_256_GCM
    #[cfg(feature = "v1-aead")]
    AES_SIV_CMAC_256, // AEAD_AES_SIV_CMAC_256
    #[cfg(feature = "v1-aead")]
    AES_SIV_CMAC_384, // AEAD_AES_SIV_CMAC_384
    #[cfg(feature = "v1-aead")]
    AES_SIV_CMAC_512, // AEAD_AES_SIV_CMAC_512
    #[cfg(feature = "v1-aead")]
    AES_128_GCM_SIV, // AEAD_AES_128_GCM_SIV
    #[cfg(feature = "v1-aead")]
    AES_256_GCM_SIV, // AEAD_AES_256_GCM_SIV
    // NOTE: IETF 版本
    #[cfg(feature = "v1-aead")]
    CHACHA20_POLY1305, // AEAD_CHACHA20_POLY1305
}

impl CipherKind {
    /// The category of the cipher
    pub fn category(&self) -> CipherCategory {
        #[cfg(feature = "v1-stream")]
        if self.is_stream() {
            return CipherCategory::Stream;
        }

        #[cfg(feature = "v1-aead")]
        if self.is_aead() {
            return CipherCategory::Aead;
        }

        return CipherCategory::None;
    }

    /// Check if the current cipher is `NONE`
    pub fn is_none(&self) -> bool {
        matches!(*self, CipherKind::NONE)
    }

    /// Check if the current cipher is a stream cipher
    #[cfg(feature = "v1-stream")]
    pub fn is_stream(&self) -> bool {
        use self::CipherKind::*;

        match *self {
            SS_TABLE | SS_RC4_MD5 | AES_128_CTR | AES_192_CTR | AES_256_CTR | AES_128_CFB1
            | AES_128_CFB8 | AES_128_CFB128 | AES_192_CFB1 | AES_192_CFB8 | AES_192_CFB128
            | AES_256_CFB1 | AES_256_CFB8 | AES_256_CFB128 | AES_128_OFB | AES_192_OFB
            | AES_256_OFB | CAMELLIA_128_CTR | CAMELLIA_192_CTR | CAMELLIA_256_CTR
            | CAMELLIA_128_CFB1 | CAMELLIA_128_CFB8 | CAMELLIA_128_CFB128 | CAMELLIA_192_CFB1
            | CAMELLIA_192_CFB8 | CAMELLIA_192_CFB128 | CAMELLIA_256_CFB1 | CAMELLIA_256_CFB8
            | CAMELLIA_256_CFB128 | CAMELLIA_128_OFB | CAMELLIA_192_OFB | CAMELLIA_256_OFB
            | RC4 | CHACHA20 => true,
            _ => false,
        }
    }

    /// Check if the current cipher is an AEAD cipher
    #[cfg(feature = "v1-aead")]
    pub fn is_aead(&self) -> bool {
        use self::CipherKind::*;

        match *self {
            AES_128_CCM
            | AES_256_CCM
            | AES_128_OCB_TAGLEN128
            | AES_192_OCB_TAGLEN128
            | AES_256_OCB_TAGLEN128
            | AES_128_GCM
            | AES_256_GCM
            | AES_SIV_CMAC_256
            | AES_SIV_CMAC_384
            | AES_SIV_CMAC_512
            | AES_128_GCM_SIV
            | AES_256_GCM_SIV
            | CHACHA20_POLY1305 => true,
            _ => false,
        }
    }

    /// Key length of the cipher
    pub fn key_len(&self) -> usize {
        use self::CipherKind::*;

        match *self {
            NONE => 0,

            #[cfg(feature = "v1-stream")]
            SS_TABLE => 0,
            // NOTE: RC4 密码本身支持 1..256 长度的 Key，
            //       但是 SS 这里把 Key 的长度限制在 16.
            #[cfg(feature = "v1-stream")]
            SS_RC4_MD5 => 16,
            #[cfg(feature = "v1-stream")]
            AES_128_CTR => Aes128Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_192_CTR => Aes192Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_256_CTR => Aes256Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_128_CFB1 => Aes128Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_128_CFB8 => Aes128Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_128_CFB128 => Aes128Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_192_CFB1 => Aes192Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_192_CFB8 => Aes192Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_192_CFB128 => Aes192Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_256_CFB1 => Aes256Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_256_CFB8 => Aes256Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_256_CFB128 => Aes256Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_128_OFB => Aes128Ofb::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_192_OFB => Aes192Ofb::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            AES_256_OFB => Aes256Ofb::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_128_CTR => Camellia128Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_192_CTR => Camellia192Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_256_CTR => Camellia256Ctr::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_128_CFB1 => Camellia128Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_128_CFB8 => Camellia128Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_128_CFB128 => Camellia128Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_192_CFB1 => Camellia192Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_192_CFB8 => Camellia192Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_192_CFB128 => Camellia192Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_256_CFB1 => Camellia256Cfb1::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_256_CFB8 => Camellia256Cfb8::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_256_CFB128 => Camellia256Cfb128::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_128_OFB => Camellia128Ofb::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_192_OFB => Camellia192Ofb::KEY_LEN,
            #[cfg(feature = "v1-stream")]
            CAMELLIA_256_OFB => Camellia256Ofb::KEY_LEN,
            // NOTE: RC4 密码本身支持 1..256 长度的 Key，
            //       但是 SS 这里把 Key 的长度限制在 16.
            #[cfg(feature = "v1-stream")]
            RC4 => 16,
            #[cfg(feature = "v1-stream")]
            CHACHA20 => Chacha20::KEY_LEN,

            // AEAD
            #[cfg(feature = "v1-aead")]
            AES_128_CCM => Aes128Ccm::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_256_CCM => Aes256Ccm::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_128_OCB_TAGLEN128 => Aes128OcbTag128::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_192_OCB_TAGLEN128 => Aes192OcbTag128::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_256_OCB_TAGLEN128 => Aes256OcbTag128::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_128_GCM => Aes128Gcm::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_256_GCM => Aes256Gcm::KEY_LEN,
            // NOTE: 注意 AES_SIV_CMAC_256 的 KEY 是 两个 AES-128 的 Key.
            //       所以是 256.
            #[cfg(feature = "v1-aead")]
            AES_SIV_CMAC_256 => AesSivCmac256::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_SIV_CMAC_384 => AesSivCmac384::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_SIV_CMAC_512 => AesSivCmac512::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_128_GCM_SIV => Aes128GcmSiv::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            AES_256_GCM_SIV => Aes256GcmSiv::KEY_LEN,
            #[cfg(feature = "v1-aead")]
            CHACHA20_POLY1305 => Chacha20Poly1305::KEY_LEN,
        }
    }

    /// Stream Cipher's initializer vector length
    #[cfg(feature = "v1-stream")]
    pub fn iv_len(&self) -> usize {
        use self::CipherKind::*;

        match *self {
            NONE => 0,
            SS_TABLE => 0,
            // NOTE: RC4 密码本身没有 IV 概念，
            //       但是 SS 这里把 Key 的长度限制在 16.
            SS_RC4_MD5 => 16,
            AES_128_CTR => Aes128Ctr::IV_LEN,
            AES_192_CTR => Aes192Ctr::IV_LEN,
            AES_256_CTR => Aes256Ctr::IV_LEN,
            AES_128_CFB1 => Aes128Cfb1::IV_LEN,
            AES_128_CFB8 => Aes128Cfb8::IV_LEN,
            AES_128_CFB128 => Aes128Cfb128::IV_LEN,
            AES_192_CFB1 => Aes192Cfb1::IV_LEN,
            AES_192_CFB8 => Aes192Cfb8::IV_LEN,
            AES_192_CFB128 => Aes192Cfb128::IV_LEN,
            AES_256_CFB1 => Aes256Cfb1::IV_LEN,
            AES_256_CFB8 => Aes256Cfb8::IV_LEN,
            AES_256_CFB128 => Aes256Cfb128::IV_LEN,
            AES_128_OFB => Aes128Ofb::IV_LEN,
            AES_192_OFB => Aes192Ofb::IV_LEN,
            AES_256_OFB => Aes256Ofb::IV_LEN,
            CAMELLIA_128_CTR => Camellia128Ctr::IV_LEN,
            CAMELLIA_192_CTR => Camellia192Ctr::IV_LEN,
            CAMELLIA_256_CTR => Camellia256Ctr::IV_LEN,
            CAMELLIA_128_CFB1 => Camellia128Cfb1::IV_LEN,
            CAMELLIA_128_CFB8 => Camellia128Cfb8::IV_LEN,
            CAMELLIA_128_CFB128 => Camellia128Cfb128::IV_LEN,
            CAMELLIA_192_CFB1 => Camellia192Cfb1::IV_LEN,
            CAMELLIA_192_CFB8 => Camellia192Cfb8::IV_LEN,
            CAMELLIA_192_CFB128 => Camellia192Cfb128::IV_LEN,
            CAMELLIA_256_CFB1 => Camellia256Cfb1::IV_LEN,
            CAMELLIA_256_CFB8 => Camellia256Cfb8::IV_LEN,
            CAMELLIA_256_CFB128 => Camellia256Cfb128::IV_LEN,
            CAMELLIA_128_OFB => Camellia128Ofb::IV_LEN,
            CAMELLIA_192_OFB => Camellia192Ofb::IV_LEN,
            CAMELLIA_256_OFB => Camellia256Ofb::IV_LEN,
            // NOTE: RC4 密码本身没有 IV 概念，
            RC4 => 0,
            CHACHA20 => Chacha20::NONCE_LEN,
            _ => panic!("only support Stream ciphers"),
        }
    }

    /// AEAD Cipher's TAG length
    #[cfg(feature = "v1-aead")]
    pub fn tag_len(&self) -> usize {
        use self::CipherKind::*;

        match *self {
            AES_128_CCM => Aes128Ccm::TAG_LEN,
            AES_256_CCM => Aes256Ccm::TAG_LEN,
            AES_128_OCB_TAGLEN128 => Aes128OcbTag128::TAG_LEN,
            AES_192_OCB_TAGLEN128 => Aes192OcbTag128::TAG_LEN,
            AES_256_OCB_TAGLEN128 => Aes256OcbTag128::TAG_LEN,
            AES_128_GCM => Aes128Gcm::TAG_LEN,
            AES_256_GCM => Aes256Gcm::TAG_LEN,
            AES_SIV_CMAC_256 => AesSivCmac256::TAG_LEN,
            AES_SIV_CMAC_384 => AesSivCmac384::TAG_LEN,
            AES_SIV_CMAC_512 => AesSivCmac512::TAG_LEN,
            AES_128_GCM_SIV => Aes128GcmSiv::TAG_LEN,
            AES_256_GCM_SIV => Aes256GcmSiv::TAG_LEN,
            CHACHA20_POLY1305 => Chacha20Poly1305::TAG_LEN,
            _ => panic!("only support AEAD ciphers"),
        }
    }

    /// AEAD Cipher's SALT length
    #[cfg(feature = "v1-aead")]
    pub fn salt_len(&self) -> usize {
        if !self.is_aead() {
            panic!("only support AEAD ciphers");
        }

        self.key_len()
    }
}

impl core::fmt::Display for CipherKind {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str(match *self {
            CipherKind::NONE => "none",

            #[cfg(feature = "v1-stream")]
            CipherKind::SS_TABLE => "table",
            #[cfg(feature = "v1-stream")]
            CipherKind::SS_RC4_MD5 => "rc4-md5",

            #[cfg(feature = "v1-stream")]
            CipherKind::AES_128_CTR => "aes-128-ctr",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_192_CTR => "aes-192-ctr",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_256_CTR => "aes-256-ctr",

            #[cfg(feature = "v1-stream")]
            CipherKind::AES_128_CFB128 => "aes-128-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_128_CFB1 => "aes-128-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_128_CFB8 => "aes-128-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::AES_192_CFB128 => "aes-192-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_192_CFB1 => "aes-192-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_192_CFB8 => "aes-192-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::AES_256_CFB128 => "aes-256-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_256_CFB1 => "aes-256-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_256_CFB8 => "aes-256-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::AES_128_OFB => "aes-128-ofb",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_192_OFB => "aes-192-ofb",
            #[cfg(feature = "v1-stream")]
            CipherKind::AES_256_OFB => "aes-256-ofb",

            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_128_CTR => "camellia-128-ctr",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_192_CTR => "camellia-192-ctr",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_256_CTR => "camellia-256-ctr",

            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_128_CFB128 => "camellia-128-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_128_CFB1 => "camellia-128-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_128_CFB8 => "camellia-128-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_192_CFB128 => "camellia-192-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_192_CFB1 => "camellia-192-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_192_CFB8 => "camellia-192-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_256_CFB128 => "camellia-256-cfb",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_256_CFB1 => "camellia-256-cfb1",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_256_CFB8 => "camellia-256-cfb8",

            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_128_OFB => "camellia-128-ofb",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_192_OFB => "camellia-192-ofb",
            #[cfg(feature = "v1-stream")]
            CipherKind::CAMELLIA_256_OFB => "camellia-256-ofb",

            #[cfg(feature = "v1-stream")]
            CipherKind::RC4 => "rc4",
            #[cfg(feature = "v1-stream")]
            CipherKind::CHACHA20 => "chacha20-ietf",

            #[cfg(feature = "v1-aead")]
            CipherKind::AES_128_GCM => "aes-128-gcm",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_256_GCM => "aes-256-gcm",

            #[cfg(feature = "v1-aead")]
            CipherKind::CHACHA20_POLY1305 => "chacha20-ietf-poly1305",

            #[cfg(feature = "v1-aead")]
            CipherKind::AES_128_CCM => "aes-128-ccm",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_256_CCM => "aes-256-ccm",

            #[cfg(feature = "v1-aead")]
            CipherKind::AES_128_GCM_SIV => "aes-128-gcm-siv",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_256_GCM_SIV => "aes-256-gcm-siv",

            #[cfg(feature = "v1-aead")]
            CipherKind::AES_128_OCB_TAGLEN128 => "aes-128-ocb-taglen128",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_192_OCB_TAGLEN128 => "aes-192-ocb-taglen128",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_256_OCB_TAGLEN128 => "aes-256-ocb-taglen128",

            #[cfg(feature = "v1-aead")]
            CipherKind::AES_SIV_CMAC_256 => "aes-siv-cmac-256",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_SIV_CMAC_384 => "aes-siv-cmac-384",
            #[cfg(feature = "v1-aead")]
            CipherKind::AES_SIV_CMAC_512 => "aes-siv-cmac-512",
        })
    }
}

impl core::str::FromStr for CipherKind {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, std::io::Error> {
        use self::CipherKind::*;

        match s.to_lowercase().as_str() {
            "plain" | "none" => Ok(NONE),
            #[cfg(feature = "v1-stream")]
            "table" | "" => Ok(SS_TABLE),
            #[cfg(feature = "v1-stream")]
            "rc4-md5" => Ok(SS_RC4_MD5),

            #[cfg(feature = "v1-stream")]
            "aes-128-ctr" => Ok(AES_128_CTR),
            #[cfg(feature = "v1-stream")]
            "aes-192-ctr" => Ok(AES_192_CTR),
            #[cfg(feature = "v1-stream")]
            "aes-256-ctr" => Ok(AES_256_CTR),

            #[cfg(feature = "v1-stream")]
            "aes-128-cfb" => Ok(AES_128_CFB128),
            #[cfg(feature = "v1-stream")]
            "aes-128-cfb1" => Ok(AES_128_CFB1),
            #[cfg(feature = "v1-stream")]
            "aes-128-cfb8" => Ok(AES_128_CFB8),
            #[cfg(feature = "v1-stream")]
            "aes-128-cfb128" => Ok(AES_128_CFB128),

            #[cfg(feature = "v1-stream")]
            "aes-192-cfb" => Ok(AES_192_CFB128),
            #[cfg(feature = "v1-stream")]
            "aes-192-cfb1" => Ok(AES_192_CFB1),
            #[cfg(feature = "v1-stream")]
            "aes-192-cfb8" => Ok(AES_192_CFB8),
            #[cfg(feature = "v1-stream")]
            "aes-192-cfb128" => Ok(AES_192_CFB128),

            #[cfg(feature = "v1-stream")]
            "aes-256-cfb" => Ok(AES_256_CFB128),
            #[cfg(feature = "v1-stream")]
            "aes-256-cfb1" => Ok(AES_256_CFB1),
            #[cfg(feature = "v1-stream")]
            "aes-256-cfb8" => Ok(AES_256_CFB8),
            #[cfg(feature = "v1-stream")]
            "aes-256-cfb128" => Ok(AES_256_CFB128),

            #[cfg(feature = "v1-stream")]
            "aes-128-ofb" => Ok(AES_128_OFB),
            #[cfg(feature = "v1-stream")]
            "aes-192-ofb" => Ok(AES_192_OFB),
            #[cfg(feature = "v1-stream")]
            "aes-256-ofb" => Ok(AES_256_OFB),

            #[cfg(feature = "v1-stream")]
            "camellia-128-ctr" => Ok(CAMELLIA_128_CTR),
            #[cfg(feature = "v1-stream")]
            "camellia-192-ctr" => Ok(CAMELLIA_192_CTR),
            #[cfg(feature = "v1-stream")]
            "camellia-256-ctr" => Ok(CAMELLIA_256_CTR),

            #[cfg(feature = "v1-stream")]
            "camellia-128-cfb" => Ok(CAMELLIA_128_CFB128),
            #[cfg(feature = "v1-stream")]
            "camellia-128-cfb1" => Ok(CAMELLIA_128_CFB1),
            #[cfg(feature = "v1-stream")]
            "camellia-128-cfb8" => Ok(CAMELLIA_128_CFB8),
            #[cfg(feature = "v1-stream")]
            "camellia-128-cfb128" => Ok(CAMELLIA_128_CFB128),

            #[cfg(feature = "v1-stream")]
            "camellia-192-cfb" => Ok(CAMELLIA_192_CFB128),
            #[cfg(feature = "v1-stream")]
            "camellia-192-cfb1" => Ok(CAMELLIA_192_CFB1),
            #[cfg(feature = "v1-stream")]
            "camellia-192-cfb8" => Ok(CAMELLIA_192_CFB8),
            #[cfg(feature = "v1-stream")]
            "camellia-192-cfb128" => Ok(CAMELLIA_192_CFB128),

            #[cfg(feature = "v1-stream")]
            "camellia-256-cfb" => Ok(CAMELLIA_256_CFB128),
            #[cfg(feature = "v1-stream")]
            "camellia-256-cfb1" => Ok(CAMELLIA_256_CFB1),
            #[cfg(feature = "v1-stream")]
            "camellia-256-cfb8" => Ok(CAMELLIA_256_CFB8),
            #[cfg(feature = "v1-stream")]
            "camellia-256-cfb128" => Ok(CAMELLIA_256_CFB128),

            #[cfg(feature = "v1-stream")]
            "camellia-128-ofb" => Ok(CAMELLIA_128_OFB),
            #[cfg(feature = "v1-stream")]
            "camellia-192-ofb" => Ok(CAMELLIA_192_OFB),
            #[cfg(feature = "v1-stream")]
            "camellia-256-ofb" => Ok(CAMELLIA_256_OFB),

            #[cfg(feature = "v1-stream")]
            "rc4" => Ok(RC4),
            #[cfg(feature = "v1-stream")]
            "chacha20-ietf" => Ok(CHACHA20),

            // AEAD 密码算法
            #[cfg(feature = "v1-aead")]
            "aes-128-gcm" => Ok(AES_128_GCM),
            #[cfg(feature = "v1-aead")]
            "aes-256-gcm" => Ok(AES_256_GCM),
            #[cfg(feature = "v1-aead")]
            "chacha20-ietf-poly1305" => Ok(CHACHA20_POLY1305),

            // NOTE: 下面的 AEAD 密码也可以使用，但是目前 ShadowSocks 的 SIP 里面并没有规范这些，所以暂时将它注释掉。
            // "aes-128-ccm" => Ok(AES_128_CCM),
            // "aes-256-ccm" => Ok(AES_256_CCM),
            // "aes-128-gcm-siv" => Ok(AES_128_GCM_SIV),
            // "aes-256-gcm-siv" => Ok(AES_256_GCM_SIV),
            // "aes-128-ocb-taglen128" => Ok(AES_128_OCB_TAGLEN128),
            // "aes-192-ocb-taglen128" => Ok(AES_192_OCB_TAGLEN128),
            // "aes-256-ocb-taglen128" => Ok(AES_256_OCB_TAGLEN128),
            // "aes-siv-cmac-256" => Ok(AES_SIV_CMAC_256),
            // "aes-siv-cmac-384" => Ok(AES_SIV_CMAC_384),
            // "aes-siv-cmac-512" => Ok(AES_SIV_CMAC_512),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "unknown cipher type",
            )),
        }
    }
}
