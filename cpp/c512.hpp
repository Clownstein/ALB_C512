#pragma once
#ifndef ALB_C512_EXPERIMENTAL
#error "C512 is research only; define ALB_C512_EXPERIMENTAL explicitly"
#endif
/**
 * ALB_C512 (C512) v2.0 — Reference Implementation in C++20
 *
 * A sponge-based authenticated encryption algorithm with:
 *   - 512-bit key, 256-bit nonce, 256-bit tag
 *   - 1024-bit internal state (32 lanes × 32 bits)
 *   - Keccak-chi S-box + NTT lattice mixing
 *   - Dual-phase rounds: a=24 (init/finalize), b=12 (data blocks)
 *
 * Header-only library. Include and use directly.
 */

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace c512 {

// ── Constants ──────────────────────────────────────────────────────────────

inline constexpr std::size_t KEY_SIZE = 64;
inline constexpr std::size_t NONCE_SIZE = 32;
inline constexpr std::size_t TAG_SIZE = 32;
inline constexpr std::size_t STATE_SIZE = 128;
inline constexpr std::size_t RATE_SIZE = 64;
inline constexpr std::size_t LANES = 32;
inline constexpr std::size_t HALF_LANES = 16;
inline constexpr std::size_t ROUNDS_A = 24;
inline constexpr std::size_t ROUNDS_B = 12;
inline constexpr std::size_t KDF_ROUNDS = 4;

using State = std::array<std::uint32_t, LANES>;
using Key = std::array<std::uint8_t, KEY_SIZE>;
using Nonce = std::array<std::uint8_t, NONCE_SIZE>;
using Tag = std::array<std::uint8_t, TAG_SIZE>;

// ── Round constants ────────────────────────────────────────────────────────

inline constexpr std::array<std::uint64_t, 24> ROUND_CONSTANTS = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL,
    0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL,
    0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL,
    0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
};

inline constexpr std::array<std::uint32_t, 16> OMEGA = {
    0x00000001U, 0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U,
    0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU,
    0x5BE0CD19U, 0x428A2F98U, 0x71374491U, 0xB5C0FBCFU,
    0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U,
};

inline std::uint32_t load_le32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
}
inline void store_le(std::uint8_t* p, std::uint64_t v, std::size_t n) {
    for (std::size_t i=0; i<n; ++i) p[i] = static_cast<std::uint8_t>(v >> (8*i));
}
// ── State conversion ───────────────────────────────────────────────────────

inline State state_from_bytes(const std::uint8_t* b) {
    State state{};
    for (std::size_t i = 0; i < LANES; ++i) {
        state[i] = load_le32(b + i * 4);
    }
    return state;
}

inline void state_to_bytes(const State& state, std::uint8_t* b) {
    for (std::size_t i = 0; i < LANES; ++i) {
        store_le(b + i * 4, state[i], 4);
    }
}

// ── Layer 1: Round Constants ───────────────────────────────────────────────

inline void apply_round_constant(State& state, std::size_t round_idx) {
    auto rc = ROUND_CONSTANTS[round_idx % 24];
    state[16] ^= static_cast<std::uint32_t>(rc);
    state[17] ^= static_cast<std::uint32_t>(rc >> 32);
}

// ── Layer 1b: Theta diffusion ──────────────────────────────────────────────

inline constexpr std::uint32_t rotl32(std::uint32_t x, unsigned n) {
    return std::rotl(x, static_cast<int>(n));
}

inline constexpr std::array<std::uint32_t, 32> ROTATION_OFFSETS = {
    0, 1, 3, 6, 10, 15, 21, 28,
    2, 5, 9, 14, 20, 27, 3, 12,
    4, 8, 13, 19, 26, 1, 7, 16,
    11, 18, 25, 31, 17, 24, 30, 22,
};

inline void apply_theta(State& state) {
    std::uint32_t parity[32]{};
    for (std::size_t i = 0; i < 32; ++i) {
        parity[i] = state[(i + 32 - 5) % 32]
                  ^ rotl32(state[(i + 5) % 32], 7)
                  ^ state[(i + 32 - 13) % 32]
                  ^ rotl32(state[(i + 13) % 32], 19);
    }
    for (std::size_t i = 0; i < 32; ++i) {
        state[i] ^= parity[i];
    }
    for (std::size_t i = 0; i < 32; ++i) {
        state[i] = rotl32(state[i], ROTATION_OFFSETS[i]);
    }
}

// ── Layer 2: Chi S-box ─────────────────────────────────────────────────────

inline void apply_chi(State& state) {
    State temp = state;
    for (std::size_t i = 0; i < 32; ++i) {
        state[i] = temp[i] ^ ((~temp[(i + 1) % 32]) & temp[(i + 2) % 32]);
    }
}

// ── Layer 3: NTT Butterfly ─────────────────────────────────────────────────

inline void ntt_butterfly_half(State& state, std::size_t offset) {
    std::size_t step = 8;
    while (step >= 1) {
        std::size_t group = 0;
        while (group < 16) {
            for (std::size_t j = 0; j < step; ++j) {
                auto idx1 = offset + group + j;
                auto idx2 = offset + group + j + step;
                auto omega_idx = (j * (16 / (step * 2))) % 16;
                auto temp = static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(state[idx2]) *
                    static_cast<std::uint64_t>(OMEGA[omega_idx])
                );
                state[idx2] = state[idx1] - temp;
                state[idx1] = state[idx1] + temp;
            }
            group += step * 2;
        }
        step /= 2;
    }
}

inline void apply_ntt_butterfly(State& state) {
    ntt_butterfly_half(state, 0);
    ntt_butterfly_half(state, 16);
    for (std::size_t i = 0; i < HALF_LANES; ++i) {
        auto a = state[i];
        auto b = state[16 + i];
        state[i] = a ^ rotl32(b, 11);
        state[16 + i] = b ^ rotl32(a, 23);
    }
}

// ── Round Key Injection ────────────────────────────────────────────────────

inline void apply_round_key(State& state, const State& round_key) {
    for (std::size_t i = 0; i < LANES; ++i) {
        state[i] ^= round_key[i];
    }
}

// ── Permutation ────────────────────────────────────────────────────────────

inline void permutation(State& state, std::size_t rounds,
                        const std::vector<State>& round_keys) {
    auto num_keys = round_keys.size();
    if (!num_keys || rounds > 24) throw std::invalid_argument("invalid permutation parameters");
    for (std::size_t i = 0; i < rounds; ++i) {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
        apply_round_key(state, round_keys[i % num_keys]);
    }
}

inline void bootstrap_permutation(State& state, std::size_t rounds) {
    for (std::size_t i = 0; i < rounds; ++i) {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
    }
}

// ── Key Schedule ───────────────────────────────────────────────────────────

inline std::vector<State> key_schedule(const Key& master_key) {
    std::array<std::uint8_t, STATE_SIZE> combined{};
    std::copy(master_key.begin(), master_key.end(), combined.begin());
    std::reverse_copy(master_key.begin(), master_key.end(), combined.begin() + KEY_SIZE);

    State c = state_from_bytes(combined.data());
    std::vector<State> round_keys;
    round_keys.reserve(24);

    for (std::uint64_t r = 0; r < 24; ++r) {
        bootstrap_permutation(c, KDF_ROUNDS);
        round_keys.push_back(c);
        c[0] ^= static_cast<std::uint32_t>(r);
        c[1] ^= 0x43353230U;
    }

    std::fill(combined.begin(), combined.end(), 0);
    return round_keys;
}

// ── State Initialization ───────────────────────────────────────────────────

inline State init_state(const Key& key, const Nonce& nonce) {
    std::array<std::uint8_t, STATE_SIZE> init_bytes{};
    std::uint64_t iv = 0x80500C1800000002ULL;
    store_le(init_bytes.data(), iv, 8);
    std::copy(key.begin(), key.end(), init_bytes.begin() + 8);
    std::copy(nonce.begin(), nonce.end(), init_bytes.begin() + 72);
    return state_from_bytes(init_bytes.data());
}

// ── Padding ────────────────────────────────────────────────────────────────

inline std::vector<std::uint8_t> pad(const std::uint8_t* data, std::size_t len,
                                     std::size_t block_size) {
    if (block_size == 0 || block_size > 128 || len > 16777216 || (len && !data)) throw std::invalid_argument("invalid research input");
    auto pad_len = block_size - (len % block_size);
    if (pad_len == 0) pad_len = block_size;
    std::vector<std::uint8_t> result(len + pad_len, 0);
    if (len > 0) std::memcpy(result.data(), data, len);
    result[len] = 0x80;
    return result;
}

// ── XOR helpers ────────────────────────────────────────────────────────────

inline void xor_block_into_state(State& state, const std::uint8_t* block,
                                 std::size_t offset) {
    for (std::size_t i = 0; i < HALF_LANES; ++i) {
        std::uint32_t v;
        v = load_le32(block + offset + i * 4);
        state[i] ^= v;
    }
}

inline void extract_keystream(const State& state, std::uint8_t* out,
                              std::size_t length) {
    for (std::size_t i = 0; i < HALF_LANES && i * 4 < length; ++i) {
        auto bytes_to_copy = std::min(std::size_t(4), length - i * 4);
        store_le(out + i * 4, state[i], bytes_to_copy);
    }
}

// ── Encrypt ────────────────────────────────────────────────────────────────

inline std::vector<std::uint8_t> encrypt(
    const Key& key,
    const Nonce& nonce,
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* plaintext, std::size_t pt_len
) {
    auto round_keys = key_schedule(key);
    State state = init_state(key, nonce);
    permutation(state, ROUNDS_A, round_keys);

    if (aad_len > 0) {
        auto aad_padded = pad(aad, aad_len, RATE_SIZE);
        auto blocks = aad_padded.size() / RATE_SIZE;
        for (std::size_t i = 0; i < blocks; ++i) {
            xor_block_into_state(state, aad_padded.data(), i * RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys);
        }
    }

    state[31] ^= 0x00000002U;

    auto full_blocks = pt_len / RATE_SIZE;
    auto remaining = pt_len % RATE_SIZE;
    std::vector<std::uint8_t> ciphertext;
    ciphertext.reserve(pt_len);

    for (std::size_t i = 0; i < full_blocks; ++i) {
        std::uint8_t ks[RATE_SIZE];
        extract_keystream(state, ks, RATE_SIZE);
        auto off = i * RATE_SIZE;
        for (std::size_t j = 0; j < RATE_SIZE; ++j) {
            ciphertext.push_back(ks[j] ^ plaintext[off + j]);
        }
        std::uint8_t absorb[RATE_SIZE]{};
        std::memcpy(absorb, plaintext + off, RATE_SIZE);
        xor_block_into_state(state, absorb, 0);
        permutation(state, ROUNDS_B, round_keys);
    }

    std::uint8_t last_block[RATE_SIZE]{};
    if (remaining > 0) {
        auto off = full_blocks * RATE_SIZE;
        std::uint8_t ks[RATE_SIZE];
        extract_keystream(state, ks, remaining);
        for (std::size_t j = 0; j < remaining; ++j) {
            ciphertext.push_back(ks[j] ^ plaintext[off + j]);
            last_block[j] = plaintext[off + j];
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(state, last_block, 0);
    permutation(state, ROUNDS_B, round_keys);

    permutation(state, ROUNDS_A, round_keys);

    state[31] ^= 0x54414732U;
    permutation(state, ROUNDS_A, round_keys);
    Tag tag{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_le(&tag[i * 4], state[i], 4);
    }

    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());
    return ciphertext;
}

// ── Decrypt ────────────────────────────────────────────────────────────────

inline std::vector<std::uint8_t> decrypt(
    const Key& key,
    const Nonce& nonce,
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* data, std::size_t data_len
) {
    if (data_len < TAG_SIZE) {
        throw std::runtime_error("C512: data too short");
    }

    auto ct_len = data_len - TAG_SIZE;
    const auto* ciphertext = data;
    const auto* tag = data + ct_len;

    auto round_keys = key_schedule(key);
    State state = init_state(key, nonce);
    permutation(state, ROUNDS_A, round_keys);

    if (aad_len > 0) {
        auto aad_padded = pad(aad, aad_len, RATE_SIZE);
        auto blocks = aad_padded.size() / RATE_SIZE;
        for (std::size_t i = 0; i < blocks; ++i) {
            xor_block_into_state(state, aad_padded.data(), i * RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys);
        }
    }

    state[31] ^= 0x00000002U;

    auto full_blocks = ct_len / RATE_SIZE;
    auto remaining = ct_len % RATE_SIZE;
    std::vector<std::uint8_t> plaintext;
    plaintext.reserve(ct_len);

    for (std::size_t i = 0; i < full_blocks; ++i) {
        std::uint8_t ks[RATE_SIZE];
        extract_keystream(state, ks, RATE_SIZE);
        auto off = i * RATE_SIZE;
        std::uint8_t absorb[RATE_SIZE]{};
        for (std::size_t j = 0; j < RATE_SIZE; ++j) {
            auto pb = ks[j] ^ ciphertext[off + j];
            plaintext.push_back(pb);
            absorb[j] = pb;
        }
        xor_block_into_state(state, absorb, 0);
        permutation(state, ROUNDS_B, round_keys);
    }

    std::uint8_t last_block[RATE_SIZE]{};
    if (remaining > 0) {
        auto off = full_blocks * RATE_SIZE;
        std::uint8_t ks[RATE_SIZE];
        extract_keystream(state, ks, remaining);
        for (std::size_t j = 0; j < remaining; ++j) {
            auto pb = ks[j] ^ ciphertext[off + j];
            plaintext.push_back(pb);
            last_block[j] = pb;
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(state, last_block, 0);
    permutation(state, ROUNDS_B, round_keys);

    permutation(state, ROUNDS_A, round_keys);

    state[31] ^= 0x54414732U;
    permutation(state, ROUNDS_A, round_keys);
    Tag expected_tag{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_le(&expected_tag[i * 4], state[i], 4);
    }

    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < TAG_SIZE; ++i) {
        diff |= expected_tag[i] ^ tag[i];
    }
    if (diff != 0) {
        std::fill(plaintext.begin(), plaintext.end(), 0);
        throw std::runtime_error("C512: authentication failed — ciphertext tampered");
    }

    return plaintext;
}

// ── XOF ───────────────────────────────────────────────────────────────────

inline std::vector<std::uint8_t> xof_output(
    const Key& key, const std::uint8_t* context, std::size_t ctx_len,
    std::size_t output_length
) {
    // Domain constants: XOF2=0x584F4632, SQZ2=0x53515A32
    auto round_keys = key_schedule(key);
    State state{};
    for (std::size_t i = 0; i < HALF_LANES; ++i) {
        state[i] = load_le32(key.data() + i * 4);
    }
    state[31] ^= 0x584F4632U;
    permutation(state, ROUNDS_A, round_keys);

    if (ctx_len > 0) {
        auto ctx_padded = pad(context, ctx_len, RATE_SIZE);
        for (std::size_t i = 0; i < ctx_padded.size() / RATE_SIZE; ++i) {
            xor_block_into_state(state, ctx_padded.data(), i * RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys);
        }
    }

    state[31] ^= 0x53515A32U;
    permutation(state, ROUNDS_A, round_keys);

    std::vector<std::uint8_t> output;
    output.reserve(output_length);
    while (output.size() < output_length) {
        auto needed = std::min(RATE_SIZE, output_length - output.size());
        std::uint8_t ks[RATE_SIZE];
        extract_keystream(state, ks, needed);
        output.insert(output.end(), ks, ks + needed);
        if (output.size() < output_length)
            permutation(state, ROUNDS_B, round_keys);
    }
    output.resize(output_length);
    return output;
}

// ── SIV ───────────────────────────────────────────────────────────────────

namespace detail {
inline Nonce siv_derive_nonce(const Key& key, const std::uint8_t* aad, std::size_t aad_len,
                               const std::uint8_t* pt, std::size_t pt_len) {
    std::vector<std::uint8_t> siv_input;
    std::uint64_t al = aad_len, pl = pt_len;
    siv_input.resize(8);
    store_le(siv_input.data(), al, 8);
    siv_input.insert(siv_input.end(), aad, aad + aad_len);
    std::uint8_t plbuf[8];
    store_le(plbuf, pl, 8);
    siv_input.insert(siv_input.end(), plbuf, plbuf + 8);
    siv_input.insert(siv_input.end(), pt, pt + pt_len);

    auto round_keys = key_schedule(key);
    State state{};
    for (std::size_t i = 0; i < HALF_LANES; ++i) {
        state[i] = load_le32(key.data() + i * 4);
    }
    state[31] ^= 0x53495632U; // SIV2
    permutation(state, ROUNDS_A, round_keys);

    if (!siv_input.empty()) {
        auto padded = pad(siv_input.data(), siv_input.size(), RATE_SIZE);
        for (std::size_t i = 0; i < padded.size() / RATE_SIZE; ++i) {
            xor_block_into_state(state, padded.data(), i * RATE_SIZE);
            permutation(state, ROUNDS_B, round_keys);
        }
    }

    state[31] ^= 0x53515A32U; // SQZ2
    permutation(state, ROUNDS_A, round_keys);

    Nonce nonce{};
    for (std::size_t i = 0; i < 8; ++i) {
        store_le(&nonce[i*4], state[i], 4);
    }
    return nonce;
}
} // namespace detail

inline std::vector<std::uint8_t> siv_encrypt(
    const Key& key,
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* plaintext, std::size_t pt_len
) {
    auto nonce = detail::siv_derive_nonce(key, aad, aad_len, plaintext, pt_len);
    auto ct_tag = encrypt(key, nonce, aad, aad_len, plaintext, pt_len);
    std::vector<std::uint8_t> result;
    result.reserve(NONCE_SIZE + ct_tag.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ct_tag.begin(), ct_tag.end());
    return result;
}

inline std::vector<std::uint8_t> siv_decrypt(
    const Key& key,
    const std::uint8_t* aad, std::size_t aad_len,
    const std::uint8_t* data, std::size_t data_len
) {
    if (data_len < NONCE_SIZE + TAG_SIZE)
        throw std::runtime_error("C512-SIV: data too short");
    Nonce nonce;
    std::copy(data, data + NONCE_SIZE, nonce.begin());
    auto plaintext = decrypt(key, nonce, aad, aad_len, data + NONCE_SIZE, data_len - NONCE_SIZE);
    auto expected = detail::siv_derive_nonce(key, aad, aad_len, plaintext.data(), plaintext.size());
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < NONCE_SIZE; ++i) diff |= nonce[i] ^ expected[i];
    if (diff != 0) {
        std::fill(plaintext.begin(), plaintext.end(), 0);
        throw std::runtime_error("C512-SIV: synthetic nonce verification failed");
    }
    return plaintext;
}

} // namespace c512
