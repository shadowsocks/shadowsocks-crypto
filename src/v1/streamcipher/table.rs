use crypto2::hash::Md5;

/// Table cipher
#[derive(Clone)]
pub struct Table {
    ebox: [u8; Self::TABLE_SIZE], // Encrypt
    dbox: [u8; Self::TABLE_SIZE], // Decrypt
}

impl core::fmt::Debug for Table {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Table").finish()
    }
}

impl Table {
    const TABLE_SIZE: usize = 256;

    pub fn new(key: &[u8], _nonce: &[u8]) -> Self {
        let h = Md5::oneshot(key);
        let a = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);

        let mut table = [0u64; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            table[i] = i as u64;
        }

        for i in 1..1024 {
            table.sort_by(|x, y| (a % (*x + i)).cmp(&(a % (*y + i))))
        }

        // EK
        let mut ebox = [0u8; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            ebox[i] = table[i] as u8;
        }

        // DK
        let mut dbox = [0u8; Self::TABLE_SIZE];
        for i in 0..Self::TABLE_SIZE {
            dbox[table[i] as usize] = i as u8;
        }

        Self { ebox, dbox }
    }

    pub fn encryptor_update(&self, plaintext_in_ciphertext_out: &mut [u8]) {
        let plen = plaintext_in_ciphertext_out.len();
        for i in 0..plen {
            let v = plaintext_in_ciphertext_out[i];
            plaintext_in_ciphertext_out[i] = self.ebox[v as usize];
        }
    }

    pub fn decryptor_update(&self, ciphertext_in_plaintext_out: &mut [u8]) {
        let clen = ciphertext_in_plaintext_out.len();
        for i in 0..clen {
            let v = ciphertext_in_plaintext_out[i];
            ciphertext_in_plaintext_out[i] = self.dbox[v as usize];
        }
    }
}

#[test]
fn test_table() {
    let key: &[u8] = b"keykeykk";
    let plaintext: &[u8] = b"hello world";

    let mut ciphertext = plaintext.to_vec();
    let cipher = Table::new(key, b"");
    cipher.encryptor_update(&mut ciphertext);

    let mut cleartext = ciphertext.clone();
    let cipher = Table::new(key, b"");
    cipher.decryptor_update(&mut cleartext);

    assert_eq!(&cleartext[..], plaintext);
}
