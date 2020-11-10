
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
        Self { }
    }
}