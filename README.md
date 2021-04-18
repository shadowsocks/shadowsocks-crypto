# shadowsocks-crypto

[![Build & Test](https://github.com/shadowsocks/shadowsocks-crypto/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/shadowsocks/shadowsocks-crypto/actions/workflows/build-and-test.yml)

shadowsocks' flavored cryptographic algorithm in pure Rust.

## Supported Ciphers

Stream Ciphers:

* [x] SS_TABLE
* [x] SS_RC4_MD5
* [x] AES_128_CTR, AES_192_CTR, AES_256_CTR
* [x] AES_128_CFB1, AES_128_CFB8, AES_128_CFB128, AES_192_CFB1, AES_192_CFB8, AES_192_CFB128, AES_256_CFB1, AES_256_CFB8, AES_256_CFB128
* [x] AES_128_OFB, AES_192_OFB, AES_256_OFB
* [x] CAMELLIA_128_CTR, CAMELLIA_192_CTR, CAMELLIA_256_CTR
* [x] CAMELLIA_128_CFB1, CAMELLIA_128_CFB8, CAMELLIA_128_CFB128, CAMELLIA_192_CFB1, CAMELLIA_192_CFB8, CAMELLIA_192_CFB128, CAMELLIA_256_CFB1, CAMELLIA_256_CFB8, CAMELLIA_256_CFB128
* [x] CAMELLIA_128_OFB, CAMELLIA_192_OFB, CAMELLIA_256_OFB
* [x] RC4
* [x] CHACHA20 (IETF Version)

AEAD Ciphers：

* [x] AES_128_CCM, AES_256_CCM
* [x] AES_128_GCM, AES_256_GCM
* [x] AES_128_GCM_SIV, AES_256_GCM_SIV
* [x] CHACHA20_POLY1305 (IETF Version)
* [x] XCHACHA20_POLY1305 (IETF Version)
* [ ] AES_128_OCB_TAGLEN128, AES_192_OCB_TAGLEN128, AES_256_OCB_TAGLEN128
* [ ] AES_SIV_CMAC_256, AES_SIV_CMAC_384, AES_SIV_CMAC_512
