# shadowsocks-crypto

[![Build & Test](https://github.com/shadowsocks/shadowsocks-crypto/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/shadowsocks/shadowsocks-crypto/actions/workflows/build-and-test.yml)

shadowsocks' flavored cryptographic algorithm in pure Rust.

## Supported Ciphers

Stream Ciphers:

* [x] SS\_TABLE
* [x] SS\_RC4\_MD5
* [x] AES\_128\_CTR, AES\_192\_CTR, AES\_256\_CTR
* [x] AES\_128\_CFB1, AES\_128\_CFB8, AES\_128\_CFB128, AES\_192\_CFB1, AES\_192\_CFB8, AES\_192\_CFB128, AES\_256\_CFB1, AES\_256\_CFB8, AES\_256\_CFB128
* [x] AES\_128\_OFB, AES\_192\_OFB, AES\_256\_OFB
* [x] CAMELLIA\_128\_CTR, CAMELLIA\_192\_CTR, CAMELLIA\_256\_CTR
* [x] CAMELLIA\_128\_CFB1, CAMELLIA\_128\_CFB8, CAMELLIA\_128\_CFB128, CAMELLIA\_192\_CFB1, CAMELLIA\_192\_CFB8, CAMELLIA\_192\_CFB128, CAMELLIA\_256\_CFB1, CAMELLIA\_256\_CFB8, CAMELLIA\_256\_CFB128
* [x] CAMELLIA\_128\_OFB, CAMELLIA\_192\_OFB, CAMELLIA\_256\_OFB
* [x] RC4
* [x] CHACHA20 (IETF Version)

AEAD Ciphers：

* [x] AES\_128\_CCM, AES\_256\_CCM
* [x] AES\_128\_GCM, AES\_256\_GCM
* [x] AES\_128\_GCM\_SIV, AES\_256\_GCM\_SIV
* [x] CHACHA20\_POLY1305 (IETF Version)
* [x] XCHACHA20\_POLY1305 (IETF Version)
* [ ] AES\_128\_OCB\_TAGLEN128, AES\_192\_OCB\_TAGLEN128, AES\_256\_OCB\_TAGLEN128
* [ ] AES\_SIV\_CMAC\_256, AES\_SIV\_CMAC\_384, AES\_SIV\_CMAC\_512
* [x] SM4\_GCM, SM4\_CCM

AEAD 2022 Ciphers ([SIP022](https://github.com/shadowsocks/shadowsocks-org/issues/196)):

* [x] AEAD2022\_BLAKE3\_AES\_128\_GCM, AEAD2022\_BLAKE3\_AES\_256\_GCM
* [x] AEAD2022\_BLAKE3\_CHACHA20\_POLY1305, AEAD2022\_BLAKE3\_CHACHA8\_POLY1305
