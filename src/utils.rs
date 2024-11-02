//! Common utilities

/// Generate random bytes into `iv_or_salt`
pub fn random_iv_or_salt(iv_or_salt: &mut [u8]) {
    use rand::Rng;

    // Gen IV or Gen Salt by KEY-LEN
    if iv_or_salt.is_empty() {
        return;
    }

    let mut rng = rand::thread_rng();
    loop {
        rng.fill(iv_or_salt);

        // https://stackoverflow.com/questions/65367552/checking-a-vecu8-to-see-if-its-all-zero
        let (prefix, aligned, suffix) = unsafe { iv_or_salt.align_to::<u128>() };
        let is_zeros =
            prefix.iter().all(|&x| x == 0) && aligned.iter().all(|&x| x == 0) && suffix.iter().all(|&x| x == 0);

        if !is_zeros {
            break;
        }
    }
}
