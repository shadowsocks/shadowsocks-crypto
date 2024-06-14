use md5::{Digest, Md5};

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
        let mut m = Md5::new();
        m.update(key);
        let h = m.finalize();
        let a = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);

        let mut table = [0u64; Self::TABLE_SIZE];

        for i in 0..table.len() {
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
        for item in plaintext_in_ciphertext_out.iter_mut() {
            *item = self.ebox[*item as usize];
        }
    }

    pub fn decryptor_update(&self, ciphertext_in_plaintext_out: &mut [u8]) {
        for item in ciphertext_in_plaintext_out {
            *item = self.dbox[*item as usize];
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

#[test]
fn test_table_box() {
    let key: &[u8] = b"password";
    let ebox: [u8; 256] = [
        157, 219, 245, 15, 85, 7, 195, 211, 55, 126, 37, 117, 249, 229, 98, 205, 254, 61, 137, 77, 253, 135, 138, 185,
        45, 100, 75, 97, 46, 22, 28, 84, 143, 160, 175, 136, 194, 2, 201, 173, 132, 155, 23, 174, 95, 54, 0, 239, 6,
        153, 180, 34, 149, 26, 19, 101, 203, 247, 214, 111, 127, 119, 81, 177, 53, 142, 13, 216, 115, 241, 202, 73, 48,
        86, 1, 11, 43, 125, 41, 121, 209, 193, 199, 51, 47, 32, 36, 90, 255, 156, 38, 108, 3, 99, 238, 179, 50, 237,
        158, 186, 110, 217, 76, 223, 118, 196, 107, 83, 39, 63, 9, 129, 72, 5, 56, 234, 91, 250, 224, 228, 251, 146,
        170, 151, 21, 10, 171, 114, 154, 172, 58, 78, 140, 197, 67, 35, 130, 92, 12, 31, 189, 166, 122, 29, 123, 113,
        215, 94, 165, 89, 221, 240, 93, 178, 150, 218, 220, 232, 144, 188, 65, 88, 52, 59, 139, 242, 71, 62, 182, 57,
        225, 147, 30, 17, 68, 243, 80, 44, 141, 4, 200, 42, 16, 102, 134, 246, 70, 244, 145, 124, 213, 8, 187, 66, 183,
        191, 40, 103, 162, 74, 87, 148, 230, 25, 120, 60, 233, 18, 176, 227, 184, 112, 20, 131, 109, 152, 14, 163, 49,
        24, 222, 181, 164, 133, 207, 104, 210, 236, 27, 106, 96, 64, 33, 116, 79, 206, 69, 212, 82, 169, 105, 235, 190,
        128, 226, 208, 168, 192, 167, 159, 161, 231, 204, 198, 248, 252,
    ];
    let dbox: [u8; 256] = [
        46, 74, 37, 92, 179, 113, 48, 5, 191, 110, 125, 75, 138, 66, 216, 3, 182, 173, 207, 54, 212, 124, 29, 42, 219,
        203, 53, 228, 30, 143, 172, 139, 85, 232, 51, 135, 86, 10, 90, 108, 196, 78, 181, 76, 177, 24, 28, 84, 72, 218,
        96, 83, 162, 64, 45, 8, 114, 169, 130, 163, 205, 17, 167, 109, 231, 160, 193, 134, 174, 236, 186, 166, 112, 71,
        199, 26, 102, 19, 131, 234, 176, 62, 238, 107, 31, 4, 73, 200, 161, 149, 87, 116, 137, 152, 147, 44, 230, 27,
        14, 93, 25, 55, 183, 197, 225, 240, 229, 106, 91, 214, 100, 59, 211, 145, 127, 68, 233, 11, 104, 61, 204, 79,
        142, 144, 189, 77, 9, 60, 243, 111, 136, 213, 40, 223, 184, 21, 35, 18, 22, 164, 132, 178, 65, 32, 158, 188,
        121, 171, 201, 52, 154, 123, 215, 49, 128, 41, 89, 0, 98, 249, 33, 250, 198, 217, 222, 148, 141, 248, 246, 239,
        122, 126, 129, 39, 43, 34, 208, 63, 153, 95, 50, 221, 168, 194, 210, 23, 99, 192, 159, 140, 242, 195, 247, 81,
        36, 6, 105, 133, 253, 82, 180, 38, 70, 56, 252, 15, 235, 224, 245, 80, 226, 7, 237, 190, 58, 146, 67, 101, 155,
        1, 156, 150, 220, 103, 118, 170, 244, 209, 119, 13, 202, 251, 157, 206, 115, 241, 227, 97, 94, 47, 151, 69,
        165, 175, 187, 2, 185, 57, 254, 12, 117, 120, 255, 20, 16, 88,
    ];

    let cipher = Table::new(key, b"");
    assert_eq!(cipher.ebox, ebox);
    assert_eq!(cipher.dbox, dbox);
}

#[test]
fn test_table_encrypt() {
    let key: &[u8] = b"password";
    let plain_text: &[u8] = b"hello world";
    let cipher_text: &[u8] = &[118, 217, 39, 39, 129, 143, 228, 129, 56, 39, 110];

    let mut cipher = Table::new(key, b"");

    let mut text_buffer = plain_text.to_vec();
    cipher.encrypt_slice(&mut text_buffer);

    assert_eq!(cipher_text, text_buffer);
}
