extern crate rand;
extern crate crypto2;
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"),
    feature = "ring"
))]
extern crate ring;

#[cfg(test)]
extern crate hex;


pub mod v1;
