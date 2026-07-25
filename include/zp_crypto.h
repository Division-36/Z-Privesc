#ifndef ZP_CRYPTO_H
#define ZP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define ZP_HASH_BYTES  32
#define ZP_HASH_HEX    (ZP_HASH_BYTES * 2 + 1)
#define ZP_SIG_BYTES   ZP_HASH_BYTES
#define ZP_SIG_HEX     (ZP_SIG_BYTES * 2 + 1)

enum zp_crypto_err {
    ZP_CRYPTO_OK = 0,
    ZP_CRYPTO_ERR_INVAL = -1,
    ZP_CRYPTO_ERR_OVERFLOW = -2,
};

int zp_blake2b_hash(uint8_t *out, size_t outlen,
                       const uint8_t *in, size_t inlen);

int zp_hmac_blake2b(uint8_t *out, size_t outlen,
                       const uint8_t *key, size_t keylen,
                       const uint8_t *msg, size_t msglen);

int zp_sign(const char *build_id, const char *build_secret,
               const uint8_t *msg, size_t msglen,
               uint8_t *sig_out, char *sig_hex_out, size_t sig_hex_cap);

int zp_verify(const char *build_id, const char *build_secret,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, size_t siglen);

int zp_hex_encode(const uint8_t *in, size_t inlen,
                     char *out, size_t out_cap);

int zp_hex_decode(const char *in, uint8_t *out, size_t out_cap);

int zp_ct_memequal(const uint8_t *a, const uint8_t *b, size_t len);

void zp_memzero(void *p, size_t len);

#endif