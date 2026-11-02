//! ALB_C512 (C512) v2.0 — Reference Implementation in Rust
//!
//! A sponge-based authenticated encryption algorithm with:
//!   - 512-bit key, 256-bit nonce, 256-bit tag
//!   - 1024-bit internal state (32 lanes × 32 bits)
//!   - Keccak-chi S-box + NTT lattice mixing
//!   - Dual-phase rounds: a=24 (init/finalize), b=12 (data blocks)
//!   - SIV mode for nonce-misuse resistance
//!   - XOF mode for arbitrary-length key derivation

use std::convert::TryInto;

// ── Constants ──────────────────────────────────────────────────────────────

pub const C512_KEY_SIZE: usize = 64;
pub const C512_NONCE_SIZE: usize = 32;
pub const C512_TAG_SIZE: usize = 32;
pub const C512_STATE_SIZE: usize = 128;
pub const C512_RATE_SIZE: usize = 64;
pub const C512_LANES: usize = 32;
pub const C512_ROUNDS_A: usize = 24;
pub const C512_ROUNDS_B: usize = 12;
pub const C512_KDF_ROUNDS: usize = 4;

const ROUND_CONSTANTS: [u64; 24] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
    0x428A2F98D728AE22, 0x7137449123EF65CD,
    0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019,
    0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE,
    0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1,
    0x9BDC06A725C71235, 0xC19BF174CF692694,
];

const OMEGA: [u32; 16] = [
    0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
    0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
    0x5BE0CD19, 0x428A2F98, 0x71374491, 0xB5C0FBCF,
    0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
];

// ── State type ─────────────────────────────────────────────────────────────

pub type C512State = [u32; C512_LANES];

// ── State conversion ───────────────────────────────────────────────────────

pub fn state_from_bytes(b: &[u8; C512_STATE_SIZE]) -> C512State {
    let mut state = [0u32; C512_LANES];
    for i in 0..C512_LANES {
        state[i] = u32::from_le_bytes(b[i*4..(i+1)*4].try_into().unwrap());
    }
    state
}

pub fn state_to_bytes(state: &C512State) -> [u8; C512_STATE_SIZE] {
    let mut b = [0u8; C512_STATE_SIZE];
    for i in 0..C512_LANES {
        b[i*4..(i+1)*4].copy_from_slice(&state[i].to_le_bytes());
    }
    b
}

// ── Layer 1: Round Constants ───────────────────────────────────────────────

fn apply_round_constant(state: &mut C512State, round_idx: usize) {
    let rc = ROUND_CONSTANTS[round_idx % 24];
    state[16] ^= rc as u32;
    state[17] ^= (rc >> 32) as u32;
}

// ── Layer 1b: Theta diffusion ──────────────────────────────────────────────

const ROTATION_OFFSETS: [u32; 32] = [
    0, 1, 3, 6, 10, 15, 21, 28,
    2, 5, 9, 14, 20, 27, 3, 12,
    4, 8, 13, 19, 26, 1, 7, 16,
    11, 18, 25, 31, 17, 24, 30, 22,
];

fn apply_theta(state: &mut C512State) {
    let mut parity = [0u32; 32];
    for i in 0..32 {
        parity[i] = state[(i + 32 - 5) % 32]
            ^ state[(i + 5) % 32].rotate_left(7)
            ^ state[(i + 32 - 13) % 32]
            ^ state[(i + 13) % 32].rotate_left(19);
    }
    for i in 0..32 {
        state[i] ^= parity[i];
    }
    for i in 0..32 {
        state[i] = state[i].rotate_left(ROTATION_OFFSETS[i]);
    }
}

// ── Layer 2: Chi S-box ─────────────────────────────────────────────────────

fn apply_chi(state: &mut C512State) {
    let temp = *state;
    for i in 0..32 {
        state[i] = temp[i] ^ ((!temp[(i + 1) % 32]) & temp[(i + 2) % 32]);
    }
}

// ── Layer 3: NTT Butterfly ─────────────────────────────────────────────────

fn ntt_butterfly_half(state: &mut C512State, offset: usize) {
    let mut step: usize = 8;
    while step >= 1 {
        let mut group: usize = 0;
        while group < 16 {
            for j in 0..step {
                let idx1 = offset + group + j;
                let idx2 = offset + group + j + step;
                let omega_idx = (j * (16 / (step * 2))) % 16;
                let temp = (state[idx2] as u64).wrapping_mul(OMEGA[omega_idx] as u64) as u32;
                state[idx2] = state[idx1].wrapping_sub(temp);
                state[idx1] = state[idx1].wrapping_add(temp);
            }
            group += step * 2;
        }
        step /= 2;
    }
}

fn apply_ntt_butterfly(state: &mut C512State) {
    ntt_butterfly_half(state, 0);
    ntt_butterfly_half(state, 16);
    for i in 0..16 {
        let a = state[i];
        let b = state[16 + i];
        state[i] = a ^ b.rotate_left(11);
        state[16 + i] = b ^ a.rotate_left(23);
    }
}

// ── Round Key Injection ────────────────────────────────────────────────────

fn apply_round_key(state: &mut C512State, round_key: &C512State) {
    for i in 0..C512_LANES {
        state[i] ^= round_key[i];
    }
}

// ── Permutation ────────────────────────────────────────────────────────────

pub fn permutation(state: &mut C512State, rounds: usize, round_keys: &[C512State]) {
    for i in 0..rounds {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
        apply_round_key(state, &round_keys[i % round_keys.len()]);
    }
}

pub fn bootstrap_permutation(state: &mut C512State, rounds: usize) {
    for i in 0..rounds {
        apply_round_constant(state, i);
        apply_theta(state);
        apply_chi(state);
        apply_ntt_butterfly(state);
    }
}

// ── Key Schedule ───────────────────────────────────────────────────────────

pub fn key_schedule(master_key: &[u8; C512_KEY_SIZE]) -> Vec<C512State> {
    assert!(std::env::var("ALB_C512_EXPERIMENTAL").as_deref() == Ok("1"), "C512 is research only; set ALB_C512_EXPERIMENTAL=1 explicitly");
    let mut rev_key = *master_key;
    rev_key.reverse();
    let mut combined = [0u8; C512_STATE_SIZE];
    combined[..64].copy_from_slice(master_key);
    combined[64..].copy_from_slice(&rev_key);
    let mut c = state_from_bytes(&combined);

    let mut round_keys = Vec::with_capacity(24);
    for r in 0..24u64 {
        bootstrap_permutation(&mut c, C512_KDF_ROUNDS);
        round_keys.push(c);
        c[0] ^= r as u32;
        c[1] ^= 0x43353230u32; // "C520" v2.0 domain
    }
    round_keys
}

// ── State Initialization ───────────────────────────────────────────────────

pub fn init_state(key: &[u8; C512_KEY_SIZE], nonce: &[u8; C512_NONCE_SIZE]) -> C512State {
    let mut init_bytes = [0u8; C512_STATE_SIZE];
    init_bytes[0..8].copy_from_slice(&0x80500C1800000002u64.to_le_bytes());
    init_bytes[8..72].copy_from_slice(key);
    init_bytes[72..104].copy_from_slice(nonce);
    state_from_bytes(&init_bytes)
}

// ── Padding ────────────────────────────────────────────────────────────────

fn pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut pad_len = block_size - (data.len() % block_size);
    if pad_len == 0 {
        pad_len = block_size;
    }
    let mut result = Vec::with_capacity(data.len() + pad_len);
    result.extend_from_slice(data);
    result.push(0x80);
    result.resize(data.len() + pad_len, 0x00);
    result
}

// ── XOR helpers ────────────────────────────────────────────────────────────

fn xor_block_into_state(state: &mut C512State, block: &[u8], offset: usize) {
    for i in 0..16 {
        let v = u32::from_le_bytes(block[offset + i*4..offset + (i+1)*4].try_into().unwrap());
        state[i] ^= v;
    }
}

fn extract_keystream(state: &C512State, length: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(C512_RATE_SIZE);
    for i in 0..16 {
        ks.extend_from_slice(&state[i].to_le_bytes());
    }
    ks.truncate(length);
    ks
}

// ── C512 Encrypt ───────────────────────────────────────────────────────────

pub fn encrypt(
    key: &[u8; C512_KEY_SIZE],
    nonce: &[u8; C512_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let round_keys = key_schedule(key);
    let mut state = init_state(key, nonce);
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    // Absorb AAD (v2.0: Phase-B rounds)
    if !aad.is_empty() {
        let aad_padded = pad(aad, C512_RATE_SIZE);
        let blocks = aad_padded.len() / C512_RATE_SIZE;
        for i in 0..blocks {
            xor_block_into_state(&mut state, &aad_padded, i * C512_RATE_SIZE);
            permutation(&mut state, C512_ROUNDS_B, &round_keys);
        }
    }

    // Domain separation
    state[31] ^= 0x00000002;

    // Absorb plaintext / emit ciphertext
    let pt_len = plaintext.len();
    let full_blocks = pt_len / C512_RATE_SIZE;
    let remaining = pt_len % C512_RATE_SIZE;
    let mut ciphertext = Vec::with_capacity(pt_len);

    for i in 0..full_blocks {
        let ks = extract_keystream(&state, C512_RATE_SIZE);
        let off = i * C512_RATE_SIZE;
        for j in 0..C512_RATE_SIZE {
            ciphertext.push(ks[j] ^ plaintext[off + j]);
        }
        let mut absorb = [0u8; C512_RATE_SIZE];
        absorb.copy_from_slice(&plaintext[off..off + C512_RATE_SIZE]);
        xor_block_into_state(&mut state, &absorb, 0);
        permutation(&mut state, C512_ROUNDS_B, &round_keys);
    }

    // Final block: partial plaintext + 0x80 padding
    let mut last_block = [0u8; C512_RATE_SIZE];
    if remaining > 0 {
        let off = full_blocks * C512_RATE_SIZE;
        let ks = extract_keystream(&state, remaining);
        for j in 0..remaining {
            ciphertext.push(ks[j] ^ plaintext[off + j]);
            last_block[j] = plaintext[off + j];
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(&mut state, &last_block, 0);
    permutation(&mut state, C512_ROUNDS_B, &round_keys);

    // Finalize
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    // Tag
    state[31] ^= 0x54414732u32;
    permutation(&mut state, C512_ROUNDS_A, &round_keys);
    let mut tag = [0u8; C512_TAG_SIZE];
    for i in 0..8 {
        tag[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }

    ciphertext.extend_from_slice(&tag);
    ciphertext
}

// ── C512 Decrypt ───────────────────────────────────────────────────────────

pub fn decrypt(
    key: &[u8; C512_KEY_SIZE],
    nonce: &[u8; C512_NONCE_SIZE],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if data.len() < C512_TAG_SIZE {
        return Err("C512: data too short");
    }

    let ct_len = data.len() - C512_TAG_SIZE;
    let ciphertext = &data[..ct_len];
    let tag = &data[ct_len..];

    let round_keys = key_schedule(key);
    let mut state = init_state(key, nonce);
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    // Absorb AAD (v2.0: Phase-B rounds)
    if !aad.is_empty() {
        let aad_padded = pad(aad, C512_RATE_SIZE);
        let blocks = aad_padded.len() / C512_RATE_SIZE;
        for i in 0..blocks {
            xor_block_into_state(&mut state, &aad_padded, i * C512_RATE_SIZE);
            permutation(&mut state, C512_ROUNDS_B, &round_keys);
        }
    }

    // Domain separation
    state[31] ^= 0x00000002;

    // Decrypt blocks
    let full_blocks = ct_len / C512_RATE_SIZE;
    let remaining = ct_len % C512_RATE_SIZE;
    let mut plaintext = Vec::with_capacity(ct_len);

    for i in 0..full_blocks {
        let ks = extract_keystream(&state, C512_RATE_SIZE);
        let off = i * C512_RATE_SIZE;
        let mut absorb = [0u8; C512_RATE_SIZE];
        for j in 0..C512_RATE_SIZE {
            let pb = ks[j] ^ ciphertext[off + j];
            plaintext.push(pb);
            absorb[j] = pb;
        }
        xor_block_into_state(&mut state, &absorb, 0);
        permutation(&mut state, C512_ROUNDS_B, &round_keys);
    }

    // Final block: partial recovered plaintext + 0x80 padding
    let mut last_block = [0u8; C512_RATE_SIZE];
    if remaining > 0 {
        let off = full_blocks * C512_RATE_SIZE;
        let ks = extract_keystream(&state, remaining);
        for j in 0..remaining {
            let pb = ks[j] ^ ciphertext[off + j];
            plaintext.push(pb);
            last_block[j] = pb;
        }
    }
    last_block[remaining] = 0x80;
    xor_block_into_state(&mut state, &last_block, 0);
    permutation(&mut state, C512_ROUNDS_B, &round_keys);

    // Finalize and verify
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    state[31] ^= 0x54414732u32;
    permutation(&mut state, C512_ROUNDS_A, &round_keys);
    let mut expected_tag = [0u8; C512_TAG_SIZE];
    for i in 0..8 {
        expected_tag[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..C512_TAG_SIZE {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err("C512: authentication failed — ciphertext tampered");
    }

    Ok(plaintext)
}

// ── C512 XOF Mode ─────────────────────────────────────────────────────────

pub fn xof(key: &[u8; C512_KEY_SIZE], context: &[u8], output_length: usize) -> Vec<u8> {
    // Uses domain constants: XOF=0x584F4632, SQZ=0x53515A32
    let round_keys = key_schedule(key);
    let mut state = [0u32; C512_LANES];
    // Load key into first 16 lanes
    for i in 0..16 {
        state[i] = u32::from_le_bytes(key[i*4..(i+1)*4].try_into().unwrap());
    }
    state[31] ^= 0x584F4632u32; // XOF2 domain
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    // Absorb context
    if !context.is_empty() {
        let ctx_padded = pad(context, C512_RATE_SIZE);
        for i in 0..(ctx_padded.len() / C512_RATE_SIZE) {
            xor_block_into_state(&mut state, &ctx_padded, i * C512_RATE_SIZE);
            permutation(&mut state, C512_ROUNDS_B, &round_keys);
        }
    }

    state[31] ^= 0x53515A32u32; // SQZ2 domain
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    // Squeeze
    let mut output = Vec::with_capacity(output_length);
    while output.len() < output_length {
        let needed = std::cmp::min(C512_RATE_SIZE, output_length - output.len());
        output.extend_from_slice(&extract_keystream(&state, needed));
        if output.len() < output_length {
            permutation(&mut state, C512_ROUNDS_B, &round_keys);
        }
    }
    output.truncate(output_length);
    output
}

// ── C512 SIV Mode ─────────────────────────────────────────────────────────

fn siv_derive_nonce(key: &[u8; C512_KEY_SIZE], aad: &[u8], plaintext: &[u8]) -> [u8; C512_NONCE_SIZE] {
    // Build length-prefixed input
    let mut siv_input = Vec::new();
    siv_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    siv_input.extend_from_slice(aad);
    siv_input.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    siv_input.extend_from_slice(plaintext);

    let round_keys = key_schedule(key);
    let mut state = [0u32; C512_LANES];
    for i in 0..16 {
        state[i] = u32::from_le_bytes(key[i*4..(i+1)*4].try_into().unwrap());
    }
    state[31] ^= 0x53495632u32; // SIV2 domain
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    if !siv_input.is_empty() {
        let padded = pad(&siv_input, C512_RATE_SIZE);
        for i in 0..(padded.len() / C512_RATE_SIZE) {
            xor_block_into_state(&mut state, &padded, i * C512_RATE_SIZE);
            permutation(&mut state, C512_ROUNDS_B, &round_keys);
        }
    }

    state[31] ^= 0x53515A32u32; // SQZ2 domain
    permutation(&mut state, C512_ROUNDS_A, &round_keys);

    let mut nonce = [0u8; C512_NONCE_SIZE];
    for i in 0..8 {
        nonce[i*4..(i+1)*4].copy_from_slice(&state[i].to_le_bytes());
    }
    nonce
}

pub fn siv_encrypt(key: &[u8; C512_KEY_SIZE], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let nonce = siv_derive_nonce(key, aad, plaintext);
    let ct_tag = encrypt(key, &nonce, aad, plaintext);
    let mut result = Vec::with_capacity(C512_NONCE_SIZE + ct_tag.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ct_tag);
    result
}

pub fn siv_decrypt(key: &[u8; C512_KEY_SIZE], aad: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < C512_NONCE_SIZE + C512_TAG_SIZE {
        return Err("C512-SIV: data too short");
    }
    let nonce: [u8; C512_NONCE_SIZE] = data[..C512_NONCE_SIZE].try_into().unwrap();
    let ct_tag = &data[C512_NONCE_SIZE..];
    let plaintext = decrypt(key, &nonce, aad, ct_tag)?;

    let expected_nonce = siv_derive_nonce(key, aad, &plaintext);
    let mut diff = 0u8;
    for i in 0..C512_NONCE_SIZE {
        diff |= nonce[i] ^ expected_nonce[i];
    }
    if diff != 0 {
        return Err("C512-SIV: synthetic nonce verification failed");
    }
    Ok(plaintext)
}

// ── Hex helpers ────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[allow(dead_code)]
fn hex_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    let bytes = s.as_bytes();
    while i + 1 < bytes.len() {
        let hi = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => panic!("invalid hex char"),
        };
        let lo = match bytes[i + 1] {
            b'0'..=b'9' => bytes[i + 1] - b'0',
            b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
            _ => panic!("invalid hex char"),
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_plaintext_empty_aad() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let ct = encrypt(&key, &nonce, &[], &[]);
        assert_eq!(ct.len(), C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &[], &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_64b_plaintext_64b_aad() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0x55u8; 64];
        let aad = [0xAAu8; 64];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ct.len(), 64 + C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_37b_plaintext_no_aad() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext: Vec<u8> = (0..37).map(|i| (i * 7 + 3) as u8).collect();
        let ct = encrypt(&key, &nonce, &[], &plaintext);
        assert_eq!(ct.len(), 37 + C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_single_byte() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0xFFu8];
        let ct = encrypt(&key, &nonce, &[], &plaintext);
        assert_eq!(ct.len(), 1 + C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_two_blocks_with_aad() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let aad = [0xDDu8; 35];
        let plaintext = [0xEEu8; 128];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ct.len(), 128 + C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_zero_key() {
        let key = [0u8; 64];
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let aad = [0x11u8; 16];
        let plaintext = [0x22u8; 32];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ct.len(), 32 + C512_TAG_SIZE);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0x55u8; 64];
        let mut ct = encrypt(&key, &nonce, &[], &plaintext);
        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &[], &ct).is_err());
    }

    #[test]
    fn test_siv_roundtrip() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let aad = [0xBBu8; 48];
        let plaintext = [0xCCu8; 100];
        let ct = siv_encrypt(&key, &aad, &plaintext);
        assert_eq!(ct.len(), C512_NONCE_SIZE + 100 + C512_TAG_SIZE);
        let pt = siv_decrypt(&key, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_siv_determinism() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let aad = [0xAAu8; 32];
        let plaintext = [0x55u8; 64];
        let ct1 = siv_encrypt(&key, &aad, &plaintext);
        let ct2 = siv_encrypt(&key, &aad, &plaintext);
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn test_xof_determinism() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let context = b"test context";
        let out1 = xof(&key, context, 128);
        let out2 = xof(&key, context, 128);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 128);
    }

    #[test]
    fn test_xof_prefix() {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let context = b"prefix test";
        let long = xof(&key, context, 128);
        let short = xof(&key, context, 64);
        assert_eq!(&long[..64], &short[..]);
    }
}

fn main() {
    println!("ALB_C512 (C512) v2.0 Rust Reference Implementation");
    println!("Running round-trip and mode tests...");

    // Round-trip: empty plaintext, empty AAD
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let ct = encrypt(&key, &nonce, &[], &[]);
        let pt = decrypt(&key, &nonce, &[], &ct).unwrap();
        assert!(pt.is_empty());
        println!("  [PASS] empty_plaintext_empty_aad round-trip");
    }

    // Round-trip: 64B plaintext, 64B AAD
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0x55u8; 64];
        let aad = [0xAAu8; 64];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        println!("  [PASS] 64B_plaintext_64B_aad round-trip");
    }

    // Round-trip: single byte
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0xFFu8];
        let ct = encrypt(&key, &nonce, &[], &plaintext);
        let pt = decrypt(&key, &nonce, &[], &ct).unwrap();
        assert_eq!(pt, plaintext);
        println!("  [PASS] single_byte round-trip");
    }

    // Round-trip: zero key
    {
        let key = [0u8; 64];
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let aad = [0x11u8; 16];
        let plaintext = [0x22u8; 32];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        println!("  [PASS] zero_key round-trip");
    }

    // Round-trip: two blocks with AAD
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let aad = [0xDDu8; 35];
        let plaintext = [0xEEu8; 128];
        let ct = encrypt(&key, &nonce, &aad, &plaintext);
        let pt = decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        println!("  [PASS] two_blocks_with_aad round-trip");
    }

    // Tamper test
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);
        let plaintext = [0x55u8; 64];
        let mut ct = encrypt(&key, &nonce, &[], &plaintext);
        ct[0] ^= 0xFF;
        assert!(decrypt(&key, &nonce, &[], &ct).is_err());
        println!("  [PASS] tampered ciphertext rejected");
    }

    // SIV round-trip
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let aad = [0xBBu8; 48];
        let plaintext = [0xCCu8; 100];
        let ct = siv_encrypt(&key, &aad, &plaintext);
        let pt = siv_decrypt(&key, &aad, &ct).unwrap();
        assert_eq!(pt, plaintext);
        println!("  [PASS] SIV round-trip");
    }

    // SIV determinism
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let aad = [0xAAu8; 32];
        let plaintext = [0x55u8; 64];
        let ct1 = siv_encrypt(&key, &aad, &plaintext);
        let ct2 = siv_encrypt(&key, &aad, &plaintext);
        assert_eq!(ct1, ct2);
        println!("  [PASS] SIV determinism");
    }

    // XOF determinism
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let context = b"test context";
        let out1 = xof(&key, context, 128);
        let out2 = xof(&key, context, 128);
        assert_eq!(out1, out2);
        assert_eq!(out1.len(), 128);
        println!("  [PASS] XOF determinism (len={})", out1.len());
    }

    // XOF prefix property
    {
        let key: [u8; 64] = core::array::from_fn(|i| i as u8);
        let context = b"prefix test";
        let long = xof(&key, context, 128);
        let short = xof(&key, context, 64);
        assert_eq!(&long[..64], &short[..]);
        println!("  [PASS] XOF prefix property");
    }

    println!("All tests passed!");
}
