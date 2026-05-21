#define _POSIX_C_SOURCE 200809L
#include "zp_crypto.h"
#include "z_privesc.h"
#include <string.h>
#include <stdio.h>

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES   32
#define BLAKE2B_KEYBYTES   64

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define G(a, b, c, d, x, y) do { \
    v[a] = v[a] + v[b] + x;      \
    v[d] = ROTR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];          \
    v[b] = ROTR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + y;      \
    v[d] = ROTR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];          \
    v[b] = ROTR64(v[b] ^ v[c], 63); \
} while (0)

struct blake2b_ctx {
    uint64_t h[8];
    uint64_t t[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  keylen;
};

static void blake2b_compress(struct blake2b_ctx *ctx, const uint8_t *block)
{
    uint64_t v[16];
    for (int i = 0; i < 8; i++)
        v[i] = ctx->h[i];
    for (int i = 0; i < 8; i++)
        v[i + 8] = blake2b_iv[i];
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = blake2b_sigma[r];
        uint64_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = (uint64_t)block[8 * s[i]] |
                   ((uint64_t)block[8 * s[i] + 1] << 8) |
                   ((uint64_t)block[8 * s[i] + 2] << 16) |
                   ((uint64_t)block[8 * s[i] + 3] << 24) |
                   ((uint64_t)block[8 * s[i] + 4] << 32) |
                   ((uint64_t)block[8 * s[i] + 5] << 40) |
                   ((uint64_t)block[8 * s[i] + 6] << 48) |
                   ((uint64_t)block[8 * s[i] + 7] << 56);
        G(v[0], v[4], v[8], v[12], m[0], m[1]);
        G(v[1], v[5], v[9], v[13], m[2], m[3]);
        G(v[2], v[6], v[10], v[14], m[4], m[5]);
        G(v[3], v[7], v[11], v[15], m[6], m[7]);
        G(v[0], v[5], v[10], v[15], m[8], m[9]);
        G(v[1], v[6], v[11], v[12], m[10], m[11]);
        G(v[2], v[7], v[8], v[13], m[12], m[13]);
        G(v[3], v[4], v[9], v[14], m[14], m[15]);
    }
    for (int i = 0; i < 8; i++)
        ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_update(struct blake2b_ctx *ctx,
                           const uint8_t *in, size_t inlen)
{
    while (inlen > 0) {
        size_t space = BLAKE2B_BLOCKBYTES - ctx->buflen;
        size_t copy = inlen < space ? inlen : space;
        memcpy(ctx->buf + ctx->buflen, in, copy);
        ctx->buflen += copy;
        in += copy;
        inlen -= copy;
        if (ctx->buflen == BLAKE2B_BLOCKBYTES) {
            ctx->t[0] += BLAKE2B_BLOCKBYTES;
            if (ctx->t[0] < BLAKE2B_BLOCKBYTES) ctx->t[1]++;
            blake2b_compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

static void blake2b_final(struct blake2b_ctx *ctx, uint8_t *out)
{
    ctx->t[0] += ctx->buflen;
    memset(ctx->buf + ctx->buflen, 0, BLAKE2B_BLOCKBYTES - ctx->buflen);
    ctx->buf[BLAKE2B_BLOCKBYTES - 1] ^= 0x80;
    blake2b_compress(ctx, ctx->buf);
    for (size_t i = 0; i < ctx->outlen; i++)
        out[i] = (uint8_t)(ctx->h[i >> 3] >> (8 * (i & 7)));
}

static int blake2b_init(struct blake2b_ctx *ctx, size_t outlen,
                        const uint8_t *key, size_t keylen)
{
    if (outlen == 0 || outlen > 64 || keylen > 64)
        return ZP_ERR_INVAL;
    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;
    ctx->keylen = (uint8_t)keylen;
    for (int i = 0; i < 8; i++)
        ctx->h[i] = blake2b_iv[i];
    uint32_t param = (uint32_t)outlen;
    ctx->h[0] ^= 0x01010000 ^ param;
    if (keylen > 0) {
        uint8_t keyblock[BLAKE2B_BLOCKBYTES];
        memset(keyblock, 0, sizeof(keyblock));
        memcpy(keyblock, key, keylen);
        blake2b_update(ctx, keyblock, BLAKE2B_BLOCKBYTES);
        zp_memzero(keyblock, sizeof(keyblock));
    }
    return ZP_OK;
}

int zp_blake2b_hash(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen)
{
    struct blake2b_ctx ctx;
    int rc = blake2b_init(&ctx, outlen, NULL, 0);
    if (rc != ZP_OK) return rc;
    blake2b_update(&ctx, in, inlen);
    blake2b_final(&ctx, out);
    zp_memzero(&ctx, sizeof(ctx));
    return ZP_OK;
}

int zp_hmac_blake2b(uint8_t *out, size_t outlen,
                    const uint8_t *key, size_t keylen,
                    const uint8_t *msg, size_t msglen)
{
    if (out == NULL || key == NULL || msg == NULL)
        return ZP_ERR_INVAL;
    uint8_t k[64];
    size_t kl = keylen;
    if (kl > 64) {
        zp_blake2b_hash(k, 32, key, keylen);
        kl = 32;
    } else {
        memcpy(k, key, kl);
    }
    uint8_t ipad[128], opad[128];
    memset(ipad, 0x36, 128);
    memset(opad, 0x5c, 128);
    for (size_t i = 0; i < kl; i++) {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    uint8_t inner[64];
    struct blake2b_ctx ctx;
    blake2b_init(&ctx, outlen, NULL, 0);
    blake2b_update(&ctx, ipad, 128);
    blake2b_update(&ctx, msg, msglen);
    blake2b_final(&ctx, inner);
    blake2b_init(&ctx, outlen, NULL, 0);
    blake2b_update(&ctx, opad, 128);
    blake2b_update(&ctx, inner, outlen);
    blake2b_final(&ctx, out);
    zp_memzero(&ctx, sizeof(ctx));
    zp_memzero(k, sizeof(k));
    zp_memzero(ipad, sizeof(ipad));
    zp_memzero(opad, sizeof(opad));
    zp_memzero(inner, sizeof(inner));
    return ZP_OK;
}

int zp_hex_encode(const uint8_t *in, size_t inlen,
                  char *out, size_t out_cap)
{
    if (in == NULL || out == NULL || out_cap < inlen * 2 + 1)
        return ZP_ERR_INVAL;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[inlen * 2] = '\0';
    return ZP_OK;
}

int zp_hex_decode(const char *in, uint8_t *out, size_t out_cap)
{
    if (in == NULL || out == NULL) return ZP_ERR_INVAL;
    size_t l = strlen(in);
    if (l % 2 != 0 || l / 2 > out_cap) return ZP_ERR_INVAL;
    for (size_t i = 0; i < l / 2; i++) {
        char hi = in[i * 2];
        char lo = in[i * 2 + 1];
        uint8_t b = 0;
        if (hi >= '0' && hi <= '9') b = (uint8_t)(hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') b = (uint8_t)(hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') b = (uint8_t)(hi - 'A' + 10) << 4;
        else return ZP_ERR_INVAL;
        if (lo >= '0' && lo <= '9') b |= (uint8_t)(lo - '0');
        else if (lo >= 'a' && lo <= 'f') b |= (uint8_t)(lo - 'a' + 10);
        else if (lo >= 'A' && lo <= 'F') b |= (uint8_t)(lo - 'A' + 10);
        else return ZP_ERR_INVAL;
        out[i] = b;
    }
    return ZP_OK;
}

int zp_ct_memequal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0 ? ZP_OK : ZP_ERR;
}

void zp_memzero(void *p, size_t len)
{
    if (p != NULL) {
        volatile unsigned char *vp = (volatile unsigned char *)p;
        for (size_t i = 0; i < len; i++)
            vp[i] = 0;
    }
}

int zp_sign(const char *build_id, const char *build_secret,
            const uint8_t *msg, size_t msglen,
            uint8_t *sig_out, char *sig_hex_out, size_t sig_hex_cap)
{
    if (build_id == NULL || build_secret == NULL ||
        msg == NULL || sig_out == NULL)
        return ZP_ERR_INVAL;
    size_t idl = strlen(build_id);
    size_t sl = strlen(build_secret);
    uint8_t key[256];
    size_t kl = idl + sl;
    if (kl > sizeof(key)) return ZP_ERR_INVAL;
    memcpy(key, build_id, idl);
    memcpy(key + idl, build_secret, sl);
    int rc = zp_hmac_blake2b(sig_out, 32, key, kl, msg, msglen);
    zp_memzero(key, kl);
    if (rc != ZP_OK) return rc;
    if (sig_hex_out != NULL && sig_hex_cap > 0)
        rc = zp_hex_encode(sig_out, 32, sig_hex_out, sig_hex_cap);
    return rc;
}

int zp_verify(const char *build_id, const char *build_secret,
              const uint8_t *msg, size_t msglen,
              const uint8_t *sig, size_t siglen)
{
    uint8_t expected[32];
    int rc = zp_sign(build_id, build_secret, msg, msglen,
                     expected, NULL, 0);
    if (rc != ZP_OK) return rc;
    rc = zp_ct_memequal(expected, sig, siglen < 32 ? siglen : 32);
    zp_memzero(expected, sizeof(expected));
    return rc;
}
