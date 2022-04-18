use crate::kind::{CipherCategory, CipherKind};

/// Dummy cipher
#[derive(Clone)]
pub struct DummyCipher;

impl core::fmt::Debug for DummyCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("DummyCipher").finish()
    }
}

impl DummyCipher {
    pub fn new() -> Self {
        Self
    }

    pub fn kind(&self) -> CipherKind {
        CipherKind::NONE
    }

    pub fn category(&self) -> CipherCategory {
        CipherCategory::None
    }

    pub fn tag_len(&self) -> usize {
        0
    }

    pub fn encrypt(&mut self, _plaintext_in_ciphertext_out: &mut [u8]) {}

    pub fn decrypt(&mut self, _ciphertext_in_plaintext_out: &mut [u8]) -> bool {
        true
    }
}

impl Default for DummyCipher {
    fn default() -> Self {
        Self::new()
    }
}
