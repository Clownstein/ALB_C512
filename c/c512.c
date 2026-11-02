/*
 * ALB_C512 (C512) v2.0 -- Portable C99 Implementation
 *
 * RESEARCH ONLY.  See c512.h for the structural defects in this cipher and
 * why it must not be used to protect real information. ALBPKG awaits review.
 *
 * A sponge-based authenticated encryption algorithm with:
 *   512-bit key, 256-bit nonce, 256-bit tag
 *   1024-bit internal state (32 lanes x 32 bits)
 *   Five-layer permutation: RoundConstant + Theta + Chi + NTT Butterfly + RoundKey
 *   Dual-phase rounds: A=24 (init/finalize), B=12 (data blocks)
 *
 * Compile standalone test:
 *   cc -std=c99 -O2 -DALB_C512_EXPERIMENTAL -DC512_MAIN -o c512_test c512.c
 */

/* This translation unit implements the research cipher, so it opts in. */
#define C512_RESEARCH_ONLY_I_UNDERSTAND_THIS_IS_NOT_SECURE 1
#include "c512.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ---- Constants --------------------------------------------------------- */

#define ROUNDS_A       24
#define ROUNDS_B       12
#define KDF_ROUNDS      4
#define HALF_LANES     16
#define MASK32         0xFFFFFFFFU

/* v2.0 domain constants */
#define DOMAIN_KS   0x43353230U  /* "C520" */
#define DOMAIN_TAG  0x54414732U  /* "TAG2" */
#define DOMAIN_SEP  0x00000002U
#define DOMAIN_XOF  0x584F4632U  /* "XOF2" */
#define DOMAIN_SQZ  0x53515A32U  /* "SQZ2" */
#define DOMAIN_SIV  0x53495632U  /* "SIV2" */

/* IV: 0x80500C1800000002 stored little-endian as two uint32_t */
#define IV_LO  0x00000002U
#define IV_HI  0x80500C18U

/* Round constants (64-bit, from fractional bits of sqrt(2), sqrt(3), SHA-256 K) */
static const uint64_t ROUND_CONSTANTS[24] = {
    UINT64_C(0x6A09E667F3BCC908), UINT64_C(0xBB67AE8584CAA73B),
    UINT64_C(0x3C6EF372FE94F82B), UINT64_C(0xA54FF53A5F1D36F1),
    UINT64_C(0x510E527FADE682D1), UINT64_C(0x9B05688C2B3E6C1F),
    UINT64_C(0x1F83D9ABFB41BD6B), UINT64_C(0x5BE0CD19137E2179),
    UINT64_C(0x428A2F98D728AE22), UINT64_C(0x7137449123EF65CD),
    UINT64_C(0xB5C0FBCFEC4D3B2F), UINT64_C(0xE9B5DBA58189DBBC),
    UINT64_C(0x3956C25BF348B538), UINT64_C(0x59F111F1B605D019),
    UINT64_C(0x923F82A4AF194F9B), UINT64_C(0xAB1C5ED5DA6D8118),
    UINT64_C(0xD807AA98A3030242), UINT64_C(0x12835B0145706FBE),
    UINT64_C(0x243185BE4EE4B28C), UINT64_C(0x550C7DC3D5FFB4E2),
    UINT64_C(0x72BE5D74F27B896F), UINT64_C(0x80DEB1FE3B1696B1),
    UINT64_C(0x9BDC06A725C71235), UINT64_C(0xC19BF174CF692694),
};

/* NTT butterfly twiddle factors */
static const uint32_t OMEGA[16] = {
    0x00000001U, 0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U,
    0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
    0x5BE0CD19U, 0x428A2F98U, 0x71374491U, 0xB5C0FBCFU,
    0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
};

/* Per-lane rotation offsets */
static const unsigned ROTATION_OFFSETS[32] = {
     0,  1,  3,  6, 10, 15, 21, 28,
     2,  5,  9, 14, 20, 27,  3, 12,
     4,  8, 13, 19, 26,  1,  7, 16,
    11, 18, 25, 31, 17, 24, 30, 22,
};

/* ---- Helpers ----------------------------------------------------------- */

static inline uint32_t rotl32(uint32_t x, unsigned n)
{
    n &= 31;
    if (n == 0)
        return x;
    return (x << n) | (x >> (32 - n));
}

static inline uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void state_from_bytes(uint32_t state[32], const uint8_t b[128])
{
    int i;
    for (i = 0; i < 32; i++)
        state[i] = load_le32(b + i * 4);
}

static void state_to_bytes(uint8_t b[128], const uint32_t state[32])
{
    int i;
    for (i = 0; i < 32; i++)
        store_le32(b + i * 4, state[i]);
}

/* Constant-time comparison; returns 0 if equal */
static int ct_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t acc = 0;
    size_t i;
    for (i = 0; i < len; i++)
        acc |= a[i] ^ b[i];
    return (acc != 0) ? -1 : 0;
}

/* ---- Permutation Layers ------------------------------------------------ */

/* Layer 1: Round constant injection */
static void apply_round_constant(uint32_t state[32], int round_idx)
{
    uint64_t rc = ROUND_CONSTANTS[round_idx % 24];
    state[16] ^= (uint32_t)(rc & MASK32);
    state[17] ^= (uint32_t)((rc >> 32) & MASK32);
}

/* Layer 2: Theta (column-parity diffusion + rotation) */
static void apply_theta(uint32_t state[32])
{
    uint32_t parity[32];
    int i;
    for (i = 0; i < 32; i++) {
        parity[i] = state[(i + 32 - 5) % 32]
                   ^ rotl32(state[(i + 5) % 32], 7)
                   ^ state[(i + 32 - 13) % 32]
                   ^ rotl32(state[(i + 13) % 32], 19);
    }
    for (i = 0; i < 32; i++)
        state[i] ^= parity[i];
    for (i = 0; i < 32; i++)
        state[i] = rotl32(state[i], ROTATION_OFFSETS[i]);
}

/* Layer 3: Chi (Keccak-style S-box) */
static void apply_chi(uint32_t state[32])
{
    uint32_t temp[32];
    int i;
    memcpy(temp, state, sizeof(temp));
    for (i = 0; i < 32; i++)
        state[i] = temp[i] ^ ((~temp[(i + 1) % 32]) & temp[(i + 2) % 32]);
}

/* Layer 4: NTT butterfly mixing */
static void ntt_butterfly_half(uint32_t state[32], int offset)
{
    int step, group, j, idx1, idx2, omega_idx;
    uint32_t temp_val;
    for (step = 8; step >= 1; step >>= 1) {
        for (group = 0; group < 16; group += step * 2) {
            for (j = 0; j < step; j++) {
                idx1 = offset + group + j;
                idx2 = offset + group + j + step;
                omega_idx = (j * (16 / (step * 2))) % 16;
                temp_val = (uint32_t)((uint64_t)state[idx2] * OMEGA[omega_idx] & MASK32);
                state[idx2] = state[idx1] - temp_val;
                state[idx1] = state[idx1] + temp_val;
            }
        }
    }
}

static void apply_ntt_butterfly(uint32_t state[32])
{
    int i;
    uint32_t a, b;
    ntt_butterfly_half(state, 0);
    ntt_butterfly_half(state, 16);
    for (i = 0; i < 16; i++) {
        a = state[i];
        b = state[16 + i];
        state[i]      = a ^ rotl32(b, 11);
        state[16 + i] = b ^ rotl32(a, 23);
    }
}

/* Layer 5: Round key injection */
static void apply_round_key(uint32_t state[32], const uint32_t round_key[32])
{
    int i;
    for (i = 0; i < 32; i++)
        state[i] ^= round_key[i];
}

/* ---- Permutation ------------------------------------------------------- */

static void permutation(uint32_t state[32], int rounds,
                        const uint32_t round_keys[][32], int num_round_keys)
{
    int i;
    for (i = 0; i < rounds; i++) {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
        apply_round_key(state, round_keys[i % num_round_keys]);
    }
}

static void bootstrap_permutation(uint32_t state[32], int rounds)
{
    int i;
    for (i = 0; i < rounds; i++) {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
    }
}

/* ---- Key Schedule ------------------------------------------------------ */

static void key_schedule(const uint8_t key[C512_KEY_SIZE],
                         uint32_t round_keys[24][32])
{
    uint8_t combined[128];
    uint32_t c[32];
    int r, i;

    /* combined = key || reverse(key) */
    memcpy(combined, key, 64);
    for (i = 0; i < 64; i++)
        combined[64 + i] = key[63 - i];

    state_from_bytes(c, combined);

    for (r = 0; r < 24; r++) {
        bootstrap_permutation(c, KDF_ROUNDS);
        memcpy(round_keys[r], c, 32 * sizeof(uint32_t));
        c[0] ^= (uint32_t)(r & MASK32);
        c[1] ^= DOMAIN_KS;
    }
}

/* ---- State Initialization ---------------------------------------------- */

static void init_state(uint32_t state[32],
                       const uint8_t key[C512_KEY_SIZE],
                       const uint8_t nonce[C512_NONCE_SIZE])
{
    uint8_t init_bytes[128];
    /* Pack IV as LE 64-bit = two LE 32-bit words */
    store_le32(init_bytes + 0, IV_LO);
    store_le32(init_bytes + 4, IV_HI);
    /* Key (64 bytes) */
    memcpy(init_bytes + 8, key, 64);
    /* Nonce (32 bytes) */
    memcpy(init_bytes + 72, nonce, 32);
    /* Zero-fill last 24 bytes */
    memset(init_bytes + 104, 0, 24);
    state_from_bytes(state, init_bytes);
}

/* ---- Checked arithmetic and buffer safety ------------------------------
 *
 * Every length used to size an allocation or a copy goes through these.  The
 * previous code computed `data_len + pad_len` and `8 + aad_len + 8 + pt_len`
 * directly, so a malformed length supplied through an integration could wrap
 * and produce an undersized allocation followed by an oversized copy.
 */

static int c512_add_ck(size_t a, size_t b, size_t *out)
{
    if (b > SIZE_MAX - a) return 0;
    *out = a + b;
    return 1;
}

/* Reject any input this build will not process.  Bounds the research API. */
static int c512_len_ok(size_t n)
{
    return n <= C512_MAX_INPUT;
}

/* True if [a, a+alen) and [b, b+blen) share any byte. */
static int c512_overlaps(const void *a, size_t alen, const void *b, size_t blen)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    if (!pa || !pb || alen == 0 || blen == 0) return 0;
    if (alen > UINTPTR_MAX - (uintptr_t)pa || blen > UINTPTR_MAX - (uintptr_t)pb) return 1;
    return ((uintptr_t)pa < (uintptr_t)pb + blen) && ((uintptr_t)pb < (uintptr_t)pa + alen);
}

/*
 * Best-effort erasure of a sensitive stack buffer.  `volatile` through a
 * function pointer keeps the compiler from eliding the stores; it is not a
 * guarantee against register spills or swap.
 */
static void *(* volatile c512_memset_fn)(void *, int, size_t) = memset;

static void c512_wipe(void *p, size_t n)
{
    if (p && n) c512_memset_fn(p, 0, n);
}

/* Little-endian 64-bit store that never shifts a size_t by 32.
 * `(size_t)x >> 32` is undefined when size_t is 32 bits wide, which the
 * previous SIV serialization did on every 32-bit target. */
static void store_le64_from_size(uint8_t *dst, size_t value)
{
    uint64_t v = (uint64_t)value;
    int i;
    for (i = 0; i < 8; i++)
        dst[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}

const char *c512_strerror(int status)
{
    switch (status) {
    case C512_OK:           return "ok";
    case C512_ERR_NULL:     return "required pointer was NULL";
    case C512_ERR_LENGTH:   return "length is invalid or exceeds C512_MAX_INPUT";
    case C512_ERR_OVERFLOW: return "length computation would overflow";
    case C512_ERR_CAPACITY: return "output buffer is too small";
    case C512_ERR_ALLOC:    return "allocation failed";
    case C512_ERR_OVERLAP:  return "input and output buffers overlap";
    case C512_ERR_AUTH:     return "authentication failed";
    case C512_ERR_SELFTEST: return "self-test failed";
    default:                return "unknown status";
    }
}

/* ---- Padding ----------------------------------------------------------- */

/* Returns padded buffer (caller must free). Sets *out_len to padded length. */
static uint8_t *c512_pad(const uint8_t *data, size_t data_len, size_t block_size,
                         size_t *out_len)
{
    size_t pad_len = block_size - (data_len % block_size);
    size_t total;
    uint8_t *buf;
    if (pad_len == 0)
        pad_len = block_size;
    if (!c512_add_ck(data_len, pad_len, &total))
        return NULL;                      /* would wrap size_t */
    if (!c512_len_ok(data_len) || total > C512_MAX_INPUT + block_size)
        return NULL;                      /* bounded research operation */
    buf = (uint8_t *)calloc(total, 1);
    if (!buf) return NULL;
    if (data_len > 0)
        memcpy(buf, data, data_len);
    buf[data_len] = 0x80;
    /* rest is already zero from calloc */
    *out_len = total;
    return buf;
}

/* ---- XOR / Keystream Helpers ------------------------------------------- */

static void xor_block_into_state(uint32_t state[32],
                                 const uint8_t *block, size_t offset)
{
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t v = load_le32(block + offset + i * 4);
        state[i] ^= v;
    }
}

static void extract_keystream(const uint32_t state[32],
                               uint8_t *out, size_t length)
{
    uint8_t rate_bytes[C512_RATE_SIZE];
    int i;
    for (i = 0; i < 16; i++)
        store_le32(rate_bytes + i * 4, state[i]);
    memcpy(out, rate_bytes, length);
}

/* ---- AEAD Encrypt ------------------------------------------------------ */

static int c512_encrypt_core(const uint8_t key[C512_KEY_SIZE],
                             const uint8_t nonce[C512_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *plaintext, size_t pt_len,
                             uint8_t *out)
{
    uint32_t round_keys[24][32];
    uint32_t state[32];
    size_t full_blocks, remaining, off, i;
    int j;
    uint8_t keystream[C512_RATE_SIZE];
    uint8_t last_block[C512_RATE_SIZE];
    uint8_t absorb[C512_RATE_SIZE];
    uint8_t tag[C512_TAG_SIZE];

    key_schedule(key, round_keys);
    init_state(state, key, nonce);
    permutation(state, ROUNDS_A, round_keys, 24);

    /* Absorb AAD (v2.0: Phase-B rounds) */
    if (aad_len > 0) {
        size_t aad_padded_len;
        uint8_t *aad_padded = c512_pad(aad, aad_len, C512_RATE_SIZE, &aad_padded_len);
        if (!aad_padded) {
            c512_wipe(state, sizeof(state));
            c512_wipe(round_keys, sizeof(round_keys));
            return C512_ERR_ALLOC;
        }
        for (i = 0; i < aad_padded_len / C512_RATE_SIZE; i++) {
            xor_block_into_state(state, aad_padded, i * C512_RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys, 24);
        }
        c512_wipe(aad_padded, aad_padded_len);
        free(aad_padded);
    }

    /* Domain separation: AAD -> plaintext */
    state[31] ^= DOMAIN_SEP;

    /* Absorb plaintext / emit ciphertext */
    full_blocks = pt_len / C512_RATE_SIZE;
    remaining = pt_len % C512_RATE_SIZE;

    for (i = 0; i < full_blocks; i++) {
        extract_keystream(state, keystream, C512_RATE_SIZE);
        off = i * C512_RATE_SIZE;
        for (j = 0; j < C512_RATE_SIZE; j++)
            out[off + j] = keystream[j] ^ plaintext[off + j];
        memcpy(absorb, plaintext + off, C512_RATE_SIZE);
        xor_block_into_state(state, absorb, 0);
        permutation(state, ROUNDS_B, round_keys, 24);
    }

    memset(last_block, 0, C512_RATE_SIZE);
    if (remaining > 0) {
        off = full_blocks * C512_RATE_SIZE;
        extract_keystream(state, keystream, (size_t)remaining);
        for (j = 0; j < (int)remaining; j++) {
            out[off + j] = keystream[j] ^ plaintext[off + j];
            last_block[j] = plaintext[off + j];
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(state, last_block, 0);
    permutation(state, ROUNDS_B, round_keys, 24);

    /* Finalize */
    permutation(state, ROUNDS_A, round_keys, 24);

    /* Tag derivation */
    state[31] ^= DOMAIN_TAG;
    permutation(state, ROUNDS_A, round_keys, 24);

    for (j = 0; j < 8; j++)
        store_le32(tag + j * 4, state[j]);
    memcpy(out + pt_len, tag, C512_TAG_SIZE);

    c512_wipe(state, sizeof(state));
    c512_wipe(round_keys, sizeof(round_keys));
    c512_wipe(keystream, sizeof(keystream));
    c512_wipe(last_block, sizeof(last_block));
    c512_wipe(absorb, sizeof(absorb));
    c512_wipe(tag, sizeof(tag));
    return C512_OK;
}

/* ---- AEAD Decrypt ------------------------------------------------------ */

static int c512_decrypt_core(const uint8_t key[C512_KEY_SIZE],
                             const uint8_t nonce[C512_NONCE_SIZE],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t *out)
{
    uint32_t round_keys[24][32];
    uint32_t state[32];
    size_t ct_len, full_blocks, remaining, off, i;
    int j;
    uint8_t keystream[C512_RATE_SIZE];
    uint8_t last_block[C512_RATE_SIZE];
    uint8_t absorb[C512_RATE_SIZE];
    uint8_t expected_tag[C512_TAG_SIZE];
    const uint8_t *tag_in;
    uint8_t pb;

    if (data_len < (size_t)C512_TAG_SIZE)
        return C512_ERR_LENGTH;

    ct_len = data_len - C512_TAG_SIZE;
    tag_in = data + ct_len;

    key_schedule(key, round_keys);
    init_state(state, key, nonce);
    permutation(state, ROUNDS_A, round_keys, 24);

    /* Absorb AAD (v2.0: Phase-B rounds) */
    if (aad_len > 0) {
        size_t aad_padded_len;
        uint8_t *aad_padded = c512_pad(aad, aad_len, C512_RATE_SIZE, &aad_padded_len);
        if (!aad_padded) {
            c512_wipe(state, sizeof(state));
            c512_wipe(round_keys, sizeof(round_keys));
            return C512_ERR_ALLOC;
        }
        for (i = 0; i < aad_padded_len / C512_RATE_SIZE; i++) {
            xor_block_into_state(state, aad_padded, i * C512_RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys, 24);
        }
        c512_wipe(aad_padded, aad_padded_len);
        free(aad_padded);
    }

    /* Domain separation */
    state[31] ^= DOMAIN_SEP;

    /* Decrypt ciphertext */
    full_blocks = ct_len / C512_RATE_SIZE;
    remaining = ct_len % C512_RATE_SIZE;

    for (i = 0; i < full_blocks; i++) {
        extract_keystream(state, keystream, C512_RATE_SIZE);
        off = i * C512_RATE_SIZE;
        memset(absorb, 0, C512_RATE_SIZE);
        for (j = 0; j < C512_RATE_SIZE; j++) {
            pb = keystream[j] ^ data[off + j];
            out[off + j] = pb;
            absorb[j] = pb;
        }
        xor_block_into_state(state, absorb, 0);
        permutation(state, ROUNDS_B, round_keys, 24);
    }

    memset(last_block, 0, C512_RATE_SIZE);
    if (remaining > 0) {
        off = full_blocks * C512_RATE_SIZE;
        extract_keystream(state, keystream, (size_t)remaining);
        for (j = 0; j < (int)remaining; j++) {
            pb = keystream[j] ^ data[off + j];
            out[off + j] = pb;
            last_block[j] = pb;
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(state, last_block, 0);
    permutation(state, ROUNDS_B, round_keys, 24);

    /* Finalize */
    permutation(state, ROUNDS_A, round_keys, 24);

    /* Tag verification */
    state[31] ^= DOMAIN_TAG;
    permutation(state, ROUNDS_A, round_keys, 24);

    for (j = 0; j < 8; j++)
        store_le32(expected_tag + j * 4, state[j]);

    if (ct_compare(expected_tag, tag_in, C512_TAG_SIZE) != 0) {
        /* Wipe the output and all sensitive state on authentication failure. */
        c512_wipe(out, ct_len);
        c512_wipe(state, sizeof(state));
        c512_wipe(round_keys, sizeof(round_keys));
        c512_wipe(keystream, sizeof(keystream));
        c512_wipe(last_block, sizeof(last_block));
        c512_wipe(absorb, sizeof(absorb));
        c512_wipe(expected_tag, sizeof(expected_tag));
        return C512_ERR_AUTH;
    }

    c512_wipe(state, sizeof(state));
    c512_wipe(round_keys, sizeof(round_keys));
    c512_wipe(keystream, sizeof(keystream));
    c512_wipe(last_block, sizeof(last_block));
    c512_wipe(absorb, sizeof(absorb));
    c512_wipe(expected_tag, sizeof(expected_tag));
    return C512_OK;
}

/* ---- XOF Mode ---------------------------------------------------------- */

static int c512_xof_core(const uint8_t key[C512_KEY_SIZE],
                         const uint8_t *context, size_t ctx_len,
                         size_t output_length, uint8_t *out)
{
    uint32_t round_keys[24][32];
    uint32_t state[32];
    size_t produced, needed, i;
    int j;

    key_schedule(key, round_keys);

    memset(state, 0, sizeof(state));
    for (j = 0; j < 16; j++)
        state[j] = load_le32(key + j * 4);
    state[31] ^= DOMAIN_XOF;

    permutation(state, ROUNDS_A, round_keys, 24);

    /* Absorb context */
    if (ctx_len > 0) {
        size_t ctx_padded_len;
        uint8_t *ctx_padded = c512_pad(context, ctx_len, C512_RATE_SIZE, &ctx_padded_len);
        if (!ctx_padded) {
            /* The old void-returning c512_xof returned here, leaving `out`
             * unchanged while reporting nothing.  A KDF caller could not tell
             * derived output from uninitialized memory. */
            c512_wipe(state, sizeof(state));
            c512_wipe(round_keys, sizeof(round_keys));
            return C512_ERR_ALLOC;
        }
        for (i = 0; i < ctx_padded_len / C512_RATE_SIZE; i++) {
            xor_block_into_state(state, ctx_padded, i * C512_RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys, 24);
        }
        c512_wipe(ctx_padded, ctx_padded_len);
        free(ctx_padded);
    }

    /* Squeeze domain separator */
    state[31] ^= DOMAIN_SQZ;
    permutation(state, ROUNDS_A, round_keys, 24);

    /* Squeeze output */
    produced = 0;
    while (produced < output_length) {
        needed = output_length - produced;
        if (needed > C512_RATE_SIZE)
            needed = C512_RATE_SIZE;
        extract_keystream(state, out + produced, needed);
        produced += needed;
        if (produced < output_length)
            permutation(state, ROUNDS_B, round_keys, 24);
    }

    c512_wipe(state, sizeof(state));
    c512_wipe(round_keys, sizeof(round_keys));
    return C512_OK;
}

/* ---- SIV Mode ---------------------------------------------------------- */

static int siv_derive_nonce(const uint8_t key[C512_KEY_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plaintext, size_t pt_len,
                            uint8_t nonce_out[C512_NONCE_SIZE])
{
    uint32_t round_keys[24][32];
    uint32_t state[32];
    uint8_t *siv_input;
    size_t siv_input_len, siv_padded_len, i;
    uint8_t *siv_padded;
    int j;

    /* Build siv_input = le64(aad_len) || aad || le64(pt_len) || plaintext.
     * Every addition is checked before it sizes the allocation, and the two
     * 64-bit length fields go through store_le64_from_size so that no size_t
     * is ever shifted by 32 (undefined when size_t is 32 bits wide). */
    if (!c512_len_ok(aad_len) || !c512_len_ok(pt_len))
        return C512_ERR_LENGTH;
    if (!c512_add_ck(8, aad_len, &siv_input_len) ||
        !c512_add_ck(siv_input_len, 8, &siv_input_len) ||
        !c512_add_ck(siv_input_len, pt_len, &siv_input_len))
        return C512_ERR_OVERFLOW;

    siv_input = (uint8_t *)calloc(siv_input_len, 1);
    if (!siv_input) return C512_ERR_ALLOC;

    store_le64_from_size(siv_input + 0, aad_len);
    if (aad_len > 0)
        memcpy(siv_input + 8, aad, aad_len);
    store_le64_from_size(siv_input + 8 + aad_len, pt_len);
    if (pt_len > 0)
        memcpy(siv_input + 8 + aad_len + 8, plaintext, pt_len);

    key_schedule(key, round_keys);

    memset(state, 0, sizeof(state));
    for (j = 0; j < 16; j++)
        state[j] = load_le32(key + j * 4);
    state[31] ^= DOMAIN_SIV;

    permutation(state, ROUNDS_A, round_keys, 24);

    if (siv_input_len > 0) {
        siv_padded = c512_pad(siv_input, siv_input_len, C512_RATE_SIZE, &siv_padded_len);
        c512_wipe(siv_input, siv_input_len);
        free(siv_input);
        if (!siv_padded) {
            /* Report the failure rather than returning with nonce_out
             * untouched, which previously left it uninitialized. */
            c512_wipe(nonce_out, C512_NONCE_SIZE);
            c512_wipe(state, sizeof(state));
            c512_wipe(round_keys, sizeof(round_keys));
            return C512_ERR_ALLOC;
        }
        for (i = 0; i < siv_padded_len / C512_RATE_SIZE; i++) {
            xor_block_into_state(state, siv_padded, i * C512_RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys, 24);
        }
        c512_wipe(siv_padded, siv_padded_len);
        free(siv_padded);
    } else {
        free(siv_input);
    }

    state[31] ^= DOMAIN_SQZ;
    permutation(state, ROUNDS_A, round_keys, 24);

    for (j = 0; j < 8; j++)
        store_le32(nonce_out + j * 4, state[j]);

    c512_wipe(state, sizeof(state));
    c512_wipe(round_keys, sizeof(round_keys));
    return C512_OK;
}

static int c512_siv_encrypt_core(const uint8_t key[C512_KEY_SIZE],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *plaintext, size_t pt_len,
                                 uint8_t *out)
{
    uint8_t nonce[C512_NONCE_SIZE];
    int rc = siv_derive_nonce(key, aad, aad_len, plaintext, pt_len, nonce);
    if (rc != C512_OK)
        return rc;
    memcpy(out, nonce, C512_NONCE_SIZE);
    rc = c512_encrypt_core(key, nonce, aad, aad_len, plaintext, pt_len,
                           out + C512_NONCE_SIZE);
    c512_wipe(nonce, sizeof(nonce));
    return rc;
}

static int c512_siv_decrypt_core(const uint8_t key[C512_KEY_SIZE],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *data, size_t data_len,
                                 uint8_t *out)
{
    const uint8_t *nonce;
    const uint8_t *ct_tag;
    size_t ct_tag_len, pt_len;
    uint8_t expected_nonce[C512_NONCE_SIZE];
    int rc;

    if (data_len < (size_t)C512_NONCE_SIZE + (size_t)C512_TAG_SIZE)
        return C512_ERR_LENGTH;

    nonce = data;
    ct_tag = data + C512_NONCE_SIZE;
    ct_tag_len = data_len - C512_NONCE_SIZE;
    pt_len = ct_tag_len - C512_TAG_SIZE;

    rc = c512_decrypt_core(key, nonce, aad, aad_len, ct_tag, ct_tag_len, out);
    if (rc != C512_OK)
        return rc;

    /* Verify synthetic nonce */
    rc = siv_derive_nonce(key, aad, aad_len, out, pt_len, expected_nonce);
    if (rc != C512_OK) {
        c512_wipe(out, pt_len);
        return rc;
    }
    if (ct_compare(nonce, expected_nonce, C512_NONCE_SIZE) != 0) {
        c512_wipe(out, pt_len);
        c512_wipe(expected_nonce, sizeof(expected_nonce));
        return C512_ERR_AUTH;
    }

    c512_wipe(expected_nonce, sizeof(expected_nonce));
    return C512_OK;
}

/* ---- Checked public API ------------------------------------------------
 *
 * Every public entry point validates its pointers, bounds its lengths,
 * computes the required output size with checked arithmetic, compares it
 * against the caller-supplied capacity, and rejects overlapping buffers
 * before touching anything.  On failure *out_len is 0 and the output buffer
 * is zeroed across the capacity the caller declared.
 */

static int c512_fail(uint8_t *out, size_t out_cap, size_t *out_len, int status)
{
    if (out_len) *out_len = 0;
    if (out && out_cap) c512_wipe(out, out_cap);
    return status;
}

static int c512_encrypt_ex(const uint8_t key[C512_KEY_SIZE],
                    const uint8_t nonce[C512_NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, size_t pt_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;
    int rc;

    if (out_len) *out_len = 0;
    if (!key || !nonce || !out) return C512_ERR_NULL;
    if (!aad && aad_len) return C512_ERR_NULL;
    if (!plaintext && pt_len) return C512_ERR_NULL;
    if (!c512_len_ok(aad_len) || !c512_len_ok(pt_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);
    if (!c512_add_ck(pt_len, C512_TAG_SIZE, &need))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERFLOW);
    if (out_cap < need)
        return c512_fail(out, out_cap, out_len, C512_ERR_CAPACITY);
    if (c512_overlaps(out, need, plaintext, pt_len) ||
        c512_overlaps(out, need, aad, aad_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERLAP);

    rc = c512_encrypt_core(key, nonce, aad, aad_len, plaintext, pt_len, out);
    if (rc != C512_OK)
        return c512_fail(out, out_cap, out_len, rc);
    if (out_len) *out_len = need;
    return C512_OK;
}

static int c512_decrypt_ex(const uint8_t key[C512_KEY_SIZE],
                    const uint8_t nonce[C512_NONCE_SIZE],
                    const uint8_t *aad, size_t aad_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;
    int rc;

    if (out_len) *out_len = 0;
    if (!key || !nonce || !data) return C512_ERR_NULL;
    if (!aad && aad_len) return C512_ERR_NULL;
    if (data_len < (size_t)C512_TAG_SIZE)
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);
    if (!c512_len_ok(aad_len) || !c512_len_ok(data_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);

    need = data_len - C512_TAG_SIZE;
    if (need && !out) return C512_ERR_NULL;
    if (out_cap < need)
        return c512_fail(out, out_cap, out_len, C512_ERR_CAPACITY);
    if (c512_overlaps(out, need, data, data_len) ||
        c512_overlaps(out, need, aad, aad_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERLAP);

    rc = c512_decrypt_core(key, nonce, aad, aad_len, data, data_len, out);
    if (rc != C512_OK)
        return c512_fail(out, out_cap, out_len, rc);
    if (out_len) *out_len = need;
    return C512_OK;
}

static int c512_xof_ex(const uint8_t key[C512_KEY_SIZE],
                const uint8_t *context, size_t ctx_len,
                size_t output_length,
                uint8_t *out, size_t out_cap, size_t *out_len)
{
    int rc;

    if (out_len) *out_len = 0;
    if (!key) return C512_ERR_NULL;
    if (!context && ctx_len) return C512_ERR_NULL;
    if (output_length && !out) return C512_ERR_NULL;
    if (!c512_len_ok(ctx_len) || !c512_len_ok(output_length))
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);
    if (out_cap < output_length)
        return c512_fail(out, out_cap, out_len, C512_ERR_CAPACITY);
    if (c512_overlaps(out, output_length, context, ctx_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERLAP);
    if (output_length == 0) return C512_OK;

    rc = c512_xof_core(key, context, ctx_len, output_length, out);
    if (rc != C512_OK)
        return c512_fail(out, out_cap, out_len, rc);
    if (out_len) *out_len = output_length;
    return C512_OK;
}

static int c512_siv_encrypt_ex(const uint8_t key[C512_KEY_SIZE],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;
    int rc;

    if (out_len) *out_len = 0;
    if (!key || !out) return C512_ERR_NULL;
    if (!aad && aad_len) return C512_ERR_NULL;
    if (!plaintext && pt_len) return C512_ERR_NULL;
    if (!c512_len_ok(aad_len) || !c512_len_ok(pt_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);
    if (!c512_add_ck(pt_len, C512_NONCE_SIZE, &need) ||
        !c512_add_ck(need, C512_TAG_SIZE, &need))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERFLOW);
    if (out_cap < need)
        return c512_fail(out, out_cap, out_len, C512_ERR_CAPACITY);
    if (c512_overlaps(out, need, plaintext, pt_len) ||
        c512_overlaps(out, need, aad, aad_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERLAP);

    rc = c512_siv_encrypt_core(key, aad, aad_len, plaintext, pt_len, out);
    if (rc != C512_OK)
        return c512_fail(out, out_cap, out_len, rc);
    if (out_len) *out_len = need;
    return C512_OK;
}

static int c512_siv_decrypt_ex(const uint8_t key[C512_KEY_SIZE],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t overhead, need;
    int rc;

    if (out_len) *out_len = 0;
    if (!key || !data) return C512_ERR_NULL;
    if (!aad && aad_len) return C512_ERR_NULL;
    overhead = (size_t)C512_NONCE_SIZE + (size_t)C512_TAG_SIZE;
    if (data_len < overhead)
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);
    if (!c512_len_ok(aad_len) || !c512_len_ok(data_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_LENGTH);

    need = data_len - overhead;
    if (need && !out) return C512_ERR_NULL;
    if (out_cap < need)
        return c512_fail(out, out_cap, out_len, C512_ERR_CAPACITY);
    if (c512_overlaps(out, need, data, data_len) ||
        c512_overlaps(out, need, aad, aad_len))
        return c512_fail(out, out_cap, out_len, C512_ERR_OVERLAP);

    rc = c512_siv_decrypt_core(key, aad, aad_len, data, data_len, out);
    if (rc != C512_OK)
        return c512_fail(out, out_cap, out_len, rc);
    if (out_len) *out_len = need;
    return C512_OK;
}

/* ---- Legacy API --------------------------------------------------------
 *
 * Unchanged signatures (except c512_xof, which now returns a status) so the
 * versioned research vectors keep running.  Each computes the capacity its
 * documented contract already requires, so the checks above still apply.
 */

static int c512_encrypt(const uint8_t key[C512_KEY_SIZE],
                 const uint8_t nonce[C512_NONCE_SIZE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *plaintext, size_t pt_len,
                 uint8_t *out)
{
    size_t need, produced;
    if (!c512_add_ck(pt_len, C512_TAG_SIZE, &need))
        return C512_ERR_OVERFLOW;
    return c512_encrypt_ex(key, nonce, aad, aad_len, plaintext, pt_len,
                           out, need, &produced);
}

static int c512_decrypt(const uint8_t key[C512_KEY_SIZE],
                 const uint8_t nonce[C512_NONCE_SIZE],
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out)
{
    size_t produced;
    if (data_len < (size_t)C512_TAG_SIZE)
        return C512_ERR_LENGTH;
    return c512_decrypt_ex(key, nonce, aad, aad_len, data, data_len,
                           out, data_len - C512_TAG_SIZE, &produced);
}

static int c512_xof(const uint8_t key[C512_KEY_SIZE],
             const uint8_t *context, size_t ctx_len,
             size_t output_length, uint8_t *out)
{
    size_t produced;
    return c512_xof_ex(key, context, ctx_len, output_length,
                       out, output_length, &produced);
}

static int c512_siv_encrypt(const uint8_t key[C512_KEY_SIZE],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *out)
{
    size_t need, produced;
    if (!c512_add_ck(pt_len, (size_t)C512_NONCE_SIZE + (size_t)C512_TAG_SIZE, &need))
        return C512_ERR_OVERFLOW;
    return c512_siv_encrypt_ex(key, aad, aad_len, plaintext, pt_len,
                               out, need, &produced);
}

static int c512_siv_decrypt(const uint8_t key[C512_KEY_SIZE],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out)
{
    size_t overhead = (size_t)C512_NONCE_SIZE + (size_t)C512_TAG_SIZE;
    size_t produced;
    if (data_len < overhead)
        return C512_ERR_LENGTH;
    return c512_siv_decrypt_ex(key, aad, aad_len, data, data_len,
                               out, data_len - overhead, &produced);
}

/* ---- Self-Test --------------------------------------------------------- */

int c512_self_test(void)
{
    uint8_t key[64];
    uint8_t nonce[32];
    uint8_t plaintext[256];
    uint8_t aad[256];
    uint8_t ct_buf[256 + C512_TAG_SIZE];
    uint8_t pt_buf[256];
    uint8_t siv_buf[C512_NONCE_SIZE + 256 + C512_TAG_SIZE];
    uint8_t xof_out1[128], xof_out2[128], xof_out3[128];
    int i, rc;

    /* key = 0x00..0x3F, nonce = 0x00..0x1F */
    for (i = 0; i < 64; i++) key[i] = (uint8_t)i;
    for (i = 0; i < 32; i++) nonce[i] = (uint8_t)i;

    /* Test 1: empty plaintext, empty AAD */
    rc = c512_encrypt(key, nonce, NULL, 0, NULL, 0, ct_buf);
    if (rc != 0) return -1;
    /* ct_buf should be just the tag (32 bytes) */
    rc = c512_decrypt(key, nonce, NULL, 0, ct_buf, C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;

    /* Test 2: 64-byte plaintext, 64-byte AAD */
    memset(plaintext, 0x55, 64);
    memset(aad, 0xAA, 64);
    rc = c512_encrypt(key, nonce, aad, 64, plaintext, 64, ct_buf);
    if (rc != 0) return -1;
    rc = c512_decrypt(key, nonce, aad, 64, ct_buf, 64 + C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;
    if (memcmp(pt_buf, plaintext, 64) != 0) return -1;

    /* Test 3: non-aligned plaintext (37 bytes) */
    {
        const char *msg = "Hello, ALB_C512 encryption test!!!";
        uint8_t pt3[37];
        memcpy(pt3, msg, 37);
        rc = c512_encrypt(key, nonce, NULL, 0, pt3, 37, ct_buf);
        if (rc != 0) return -1;
        rc = c512_decrypt(key, nonce, NULL, 0, ct_buf, 37 + C512_TAG_SIZE, pt_buf);
        if (rc != 0) return -1;
        if (memcmp(pt_buf, pt3, 37) != 0) return -1;
    }

    /* Test 4: tampered ciphertext */
    memset(plaintext, 0x55, 64);
    memset(aad, 0xAA, 64);
    rc = c512_encrypt(key, nonce, aad, 64, plaintext, 64, ct_buf);
    if (rc != 0) return -1;
    ct_buf[0] ^= 0xFF;
    rc = c512_decrypt(key, nonce, aad, 64, ct_buf, 64 + C512_TAG_SIZE, pt_buf);
    if (rc != C512_ERR_AUTH) return -1;  /* must report authentication failure */

    /* Test 5: single byte */
    {
        uint8_t one = 0xFF;
        rc = c512_encrypt(key, nonce, NULL, 0, &one, 1, ct_buf);
        if (rc != 0) return -1;
        rc = c512_decrypt(key, nonce, NULL, 0, ct_buf, 1 + C512_TAG_SIZE, pt_buf);
        if (rc != 0) return -1;
        if (pt_buf[0] != 0xFF) return -1;
    }

    /* Test 6: empty AAD with plaintext */
    memset(plaintext, 0x55, 64);
    rc = c512_encrypt(key, nonce, NULL, 0, plaintext, 64, ct_buf);
    if (rc != 0) return -1;
    rc = c512_decrypt(key, nonce, NULL, 0, ct_buf, 64 + C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;
    if (memcmp(pt_buf, plaintext, 64) != 0) return -1;

    /* Test 7: nonempty AAD, empty plaintext */
    memset(aad, 0xAA, 64);
    rc = c512_encrypt(key, nonce, aad, 64, NULL, 0, ct_buf);
    if (rc != 0) return -1;
    rc = c512_decrypt(key, nonce, aad, 64, ct_buf, C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;

    /* Test 8: two full blocks with AAD */
    memset(plaintext, 0xEE, 128);
    memset(aad, 0xDD, 33);
    rc = c512_encrypt(key, nonce, aad, 33, plaintext, 128, ct_buf);
    if (rc != 0) return -1;
    rc = c512_decrypt(key, nonce, aad, 33, ct_buf, 128 + C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;
    if (memcmp(pt_buf, plaintext, 128) != 0) return -1;

    /* Test 9: zero key */
    {
        uint8_t zero_key[64];
        uint8_t pt9[32], aad9[16];
        memset(zero_key, 0, 64);
        memset(pt9, 0x22, 32);
        memset(aad9, 0x11, 16);
        rc = c512_encrypt(zero_key, nonce, aad9, 16, pt9, 32, ct_buf);
        if (rc != 0) return -1;
        rc = c512_decrypt(zero_key, nonce, aad9, 16, ct_buf, 32 + C512_TAG_SIZE, pt_buf);
        if (rc != 0) return -1;
        if (memcmp(pt_buf, pt9, 32) != 0) return -1;
    }

    /* Test 10: SIV round-trip */
    memset(plaintext, 0x55, 64);
    memset(aad, 0xAA, 64);
    rc = c512_siv_encrypt(key, aad, 64, plaintext, 64, siv_buf);
    if (rc != 0) return -1;
    rc = c512_siv_decrypt(key, aad, 64, siv_buf,
                          C512_NONCE_SIZE + 64 + C512_TAG_SIZE, pt_buf);
    if (rc != 0) return -1;
    if (memcmp(pt_buf, plaintext, 64) != 0) return -1;

    /* Test 11: SIV determinism */
    {
        uint8_t siv_buf2[C512_NONCE_SIZE + 64 + C512_TAG_SIZE];
        rc = c512_siv_encrypt(key, aad, 64, plaintext, 64, siv_buf2);
        if (rc != 0) return -1;
        if (memcmp(siv_buf, siv_buf2, C512_NONCE_SIZE + 64 + C512_TAG_SIZE) != 0)
            return -1;
    }

    /* Test 12: SIV tamper detection */
    siv_buf[40] ^= 0x01;
    rc = c512_siv_decrypt(key, aad, 64, siv_buf,
                          C512_NONCE_SIZE + 64 + C512_TAG_SIZE, pt_buf);
    if (rc != C512_ERR_AUTH) return -1;  /* must report authentication failure */

    /* Test 13: XOF determinism */
    {
        const char *ctx = "test context";
        if (c512_xof(key, (const uint8_t *)ctx, 12, 64, xof_out1) != C512_OK) return -1;
        if (c512_xof(key, (const uint8_t *)ctx, 12, 64, xof_out2) != C512_OK) return -1;
        if (memcmp(xof_out1, xof_out2, 64) != 0) return -1;
    }

    /* Test 14: XOF different contexts */
    {
        const char *ctx2 = "other context";
        if (c512_xof(key, (const uint8_t *)ctx2, 13, 64, xof_out3) != C512_OK) return -1;
        if (memcmp(xof_out1, xof_out3, 64) == 0) return -1;  /* should differ */
    }

    /* Test 15: XOF variable length (prefix property) */
    {
        uint8_t xof_128[128], xof_64[64];
        const char *ctx = "test";
        if (c512_xof(key, (const uint8_t *)ctx, 4, 128, xof_128) != C512_OK) return -1;
        if (c512_xof(key, (const uint8_t *)ctx, 4, 64, xof_64) != C512_OK) return -1;
        if (memcmp(xof_128, xof_64, 64) != 0) return -1;
    }

    /* Test 16: capacity checks reject an undersized output buffer */
    {
        uint8_t small[8];
        size_t produced = 12345;
        memset(plaintext, 0x11, 64);
        rc = c512_encrypt_ex(key, nonce, NULL, 0, plaintext, 64,
                             small, sizeof(small), &produced);
        if (rc != C512_ERR_CAPACITY) return -1;
        if (produced != 0) return -1;
        rc = c512_xof_ex(key, NULL, 0, 64, small, sizeof(small), &produced);
        if (rc != C512_ERR_CAPACITY) return -1;
        if (produced != 0) return -1;
    }

    /* Test 17: NULL pointers are rejected, not dereferenced */
    {
        size_t produced;
        if (c512_encrypt_ex(NULL, nonce, NULL, 0, NULL, 0,
                            ct_buf, sizeof(ct_buf), &produced) != C512_ERR_NULL)
            return -1;
        if (c512_encrypt_ex(key, nonce, NULL, 5, NULL, 0,
                            ct_buf, sizeof(ct_buf), &produced) != C512_ERR_NULL)
            return -1;
        if (c512_xof_ex(key, NULL, 0, 16, NULL, 16, &produced) != C512_ERR_NULL)
            return -1;
    }

    /* Test 18: over-long inputs are refused before any allocation */
    {
        size_t produced;
        rc = c512_encrypt_ex(key, nonce, NULL, 0, plaintext,
                             C512_MAX_INPUT + 1,
                             ct_buf, sizeof(ct_buf), &produced);
        if (rc != C512_ERR_LENGTH) return -1;
        rc = c512_siv_encrypt_ex(key, NULL, C512_MAX_INPUT + 1, NULL, 0,
                                 siv_buf, sizeof(siv_buf), &produced);
        if (rc != C512_ERR_NULL && rc != C512_ERR_LENGTH) return -1;
    }

    /* Test 19: overlapping input and output buffers are refused */
    {
        uint8_t shared[64 + C512_TAG_SIZE];
        size_t produced;
        memset(shared, 0x33, sizeof(shared));
        rc = c512_encrypt_ex(key, nonce, NULL, 0, shared, 64,
                             shared, sizeof(shared), &produced);
        if (rc != C512_ERR_OVERLAP) return -1;
    }

    /* Test 20: length addition overflow is caught, not wrapped */
    {
        size_t produced;
        rc = c512_encrypt_ex(key, nonce, NULL, 0, plaintext,
                             SIZE_MAX - 4, ct_buf, sizeof(ct_buf), &produced);
        if (rc != C512_ERR_LENGTH && rc != C512_ERR_OVERFLOW) return -1;
    }

    /* Test 21: out_len reports the byte count actually produced */
    {
        size_t produced = 0;
        memset(plaintext, 0x77, 100);
        rc = c512_encrypt_ex(key, nonce, NULL, 0, plaintext, 100,
                             ct_buf, sizeof(ct_buf), &produced);
        if (rc != C512_OK) return -1;
        if (produced != 100 + C512_TAG_SIZE) return -1;
        produced = 0;
        rc = c512_decrypt_ex(key, nonce, NULL, 0, ct_buf, 100 + C512_TAG_SIZE,
                             pt_buf, sizeof(pt_buf), &produced);
        if (rc != C512_OK) return -1;
        if (produced != 100) return -1;
        if (memcmp(pt_buf, plaintext, 100) != 0) return -1;
    }

    /* Test 22: authentication failure is distinguishable from other errors */
    {
        size_t produced;
        memset(plaintext, 0x99, 32);
        rc = c512_encrypt_ex(key, nonce, NULL, 0, plaintext, 32,
                             ct_buf, sizeof(ct_buf), &produced);
        if (rc != C512_OK) return -1;
        ct_buf[3] ^= 0x80;
        rc = c512_decrypt_ex(key, nonce, NULL, 0, ct_buf, 32 + C512_TAG_SIZE,
                             pt_buf, sizeof(pt_buf), &produced);
        if (rc != C512_ERR_AUTH) return -1;
        if (produced != 0) return -1;
    }

    return C512_OK;
}

/* ---- Standalone main --------------------------------------------------- */

#ifdef C512_MAIN
#include <stdio.h>
int main(void) {
    printf("NOTE: C512 is a RESEARCH cipher with known structural defects.\n"
           "      Do not use it to protect real information. See c512.h.\n\n");
    if (c512_self_test() == C512_OK) {
        printf("All C512 v2.0 self-tests PASSED.\n");
        return 0;
    }
    printf("C512 self-tests FAILED!\n");
    return 1;
}
#endif

static int valid_region(const void *p, size_t n) {
    return n == 0 || (p && n <= UINTPTR_MAX - (uintptr_t)p);
}
static int overlaps(const void *a, size_t an, const void *b, size_t bn) {
    if (!an || !bn) return 0;
    return (uintptr_t)a < (uintptr_t)b + bn && (uintptr_t)b < (uintptr_t)a + an;
}
c512_status c512_research_run(c512_operation op,
    const uint8_t *key, size_t key_len, const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
    size_t requested, uint8_t *out, size_t capacity, size_t *written) {
    size_t need;
    int rc;
    if (!written) return C512_INVALID;
    /* The written pointer is part of the alias contract, too. */
    if (!valid_region(written, sizeof(*written)) || !valid_region(out,capacity) ||
        !valid_region(key,key_len) || !valid_region(nonce,nonce_len) ||
        !valid_region(aad,aad_len) || !valid_region(input,input_len)) return C512_INVALID;
    if (overlaps(written,sizeof(*written),out,capacity) ||
        overlaps(written,sizeof(*written),key,key_len) ||
        overlaps(written,sizeof(*written),nonce,nonce_len) ||
        overlaps(written,sizeof(*written),aad,aad_len) ||
        overlaps(written,sizeof(*written),input,input_len)) return C512_OVERLAP;
    *written = 0;
    if (key_len != 64 || aad_len > C512_RESEARCH_LIMIT || input_len > C512_RESEARCH_LIMIT ||
        requested > C512_RESEARCH_LIMIT) return C512_INVALID;
    if (op == C512_ENCRYPT || op == C512_DECRYPT) {
        if (nonce_len != 32) return C512_INVALID;
    } else if (nonce_len) return C512_INVALID;
    switch (op) {
      case C512_ENCRYPT: need = input_len + 32; break;
      case C512_DECRYPT: if (input_len < 32) return C512_INVALID; need=input_len-32; break;
      case C512_SIV_ENCRYPT: need=input_len+64; break;
      case C512_SIV_DECRYPT: if (input_len < 64) return C512_INVALID; need=input_len-64; break;
      case C512_XOF: if (input_len) return C512_INVALID; need=requested; break;
      default: return C512_INVALID;
    }
    if (op != C512_XOF && requested) return C512_INVALID;
    if (capacity < need || (!out && need)) return C512_CAPACITY;
    if (overlaps(out,capacity,key,key_len) || overlaps(out,capacity,nonce,nonce_len) ||
        overlaps(out,capacity,aad,aad_len) || overlaps(out,capacity,input,input_len)) return C512_OVERLAP;
    switch (op) {
      case C512_ENCRYPT: rc=c512_encrypt(key,nonce,aad,aad_len,input,input_len,out); break;
      case C512_DECRYPT: rc=c512_decrypt(key,nonce,aad,aad_len,input,input_len,out); break;
      case C512_SIV_ENCRYPT: rc=c512_siv_encrypt(key,aad,aad_len,input,input_len,out); break;
      case C512_SIV_DECRYPT: rc=c512_siv_decrypt(key,aad,aad_len,input,input_len,out); break;
      default: rc=c512_xof(key,aad,aad_len,requested,out); break;
    }
    if (rc) {
        volatile uint8_t *wipe=out;
        size_t i; for(i=0;i<need;i++) wipe[i]=0;
        return C512_FAILED;
    }
    *written=need;
    return C512_OK;
}
