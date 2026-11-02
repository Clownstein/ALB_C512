// Package c512 implements ALB_C512 (C512) v2.0, a sponge-based authenticated
// encryption algorithm with 512-bit key, 256-bit nonce, and 256-bit tag.
//
// The internal state is 1024 bits (32 lanes x 32 bits) with a five-layer
// permutation: RoundConstant + Theta + Chi + NTT Butterfly + RoundKey.
//
// Modes provided: AEAD, SIV (misuse-resistant), XOF (extendable output).
package c512

import (
 "os"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// ---------- public constants -------------------------------------------------

const (
	KeySize   = 64  // bytes (512 bits)
	NonceSize = 32  // bytes (256 bits)
	TagSize   = 32  // bytes (256 bits)
	StateSize = 128 // bytes (1024 bits)
	RateSize  = 64  // bytes (512 bits)
)

// ---------- internal constants -----------------------------------------------

const (
	lanes    = 32
	halfLanes = 16
	roundsA  = 24 // init / finalize
	roundsB  = 12 // per data block
	kdfRounds = 4 // key schedule bootstrap

	mask32 = 0xFFFFFFFF

	// v2.0 domain constants
	domainKS  = 0x43353230 // "C520"
	domainTAG = 0x54414732 // "TAG2"
	domainSEP = 0x00000002 // AAD-to-plaintext separator
	domainXOF = 0x584F4632 // "XOF2"
	domainSQZ = 0x53515A32 // "SQZ2"
	domainSIV = 0x53495632 // "SIV2"

	// v2.0 init vector
	c512IV = 0x80500C1800000002
)

// Round constants (fractional bits of sqrt(2), sqrt(3), SHA-256 K[0..23]).
var roundConstants = [24]uint64{
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
}

// NTT butterfly twiddle factors.
var omega = [16]uint32{
	0x00000001, 0x6A09E667, 0xBB67AE85, 0x3C6EF372,
	0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
	0x5BE0CD19, 0x428A2F98, 0x71374491, 0xB5C0FBCF,
	0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4,
}

// Per-lane rotation offsets.
var rotationOffsets = [32]uint{
	0, 1, 3, 6, 10, 15, 21, 28,
	2, 5, 9, 14, 20, 27, 3, 12,
	4, 8, 13, 19, 26, 1, 7, 16,
	11, 18, 25, 31, 17, 24, 30, 22,
}

// ---------- errors -----------------------------------------------------------

var (
	ErrAuthFailed = errors.New("c512: authentication failed")
	ErrDataShort  = errors.New("c512: data too short")
)

// ---------- helpers ----------------------------------------------------------

func rotl32(x uint32, n uint) uint32 {
	return bits.RotateLeft32(x, int(n))
}

// mod32 returns ((i % 32) + 32) % 32 for possibly-negative i.
func mod32(i int) int {
	return ((i % 32) + 32) % 32
}

func stateFromBytes(b []byte) [lanes]uint32 {
	var s [lanes]uint32
	for i := 0; i < lanes; i++ {
		s[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return s
}

func stateToBytes(s *[lanes]uint32) []byte {
	out := make([]byte, StateSize)
	for i := 0; i < lanes; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], s[i])
	}
	return out
}

// ---------- permutation layers -----------------------------------------------

// Layer 1: Round Constants
func applyRoundConstant(s *[lanes]uint32, roundIdx int) {
	rc := roundConstants[roundIdx%24]
	s[16] ^= uint32(rc & mask32)
	s[17] ^= uint32((rc >> 32) & mask32)
}

// Layer 2: Theta (column-parity diffusion)
func applyTheta(s *[lanes]uint32) {
	var parity [32]uint32
	for i := 0; i < 32; i++ {
		parity[i] = s[mod32(i-5)] ^
			rotl32(s[mod32(i+5)], 7) ^
			s[mod32(i-13)] ^
			rotl32(s[mod32(i+13)], 19)
	}
	for i := 0; i < 32; i++ {
		s[i] ^= parity[i]
	}
	for i := 0; i < 32; i++ {
		s[i] = rotl32(s[i], rotationOffsets[i])
	}
}

// Layer 3: Chi (Keccak S-box)
func applyChi(s *[lanes]uint32) {
	var tmp [lanes]uint32
	copy(tmp[:], s[:])
	for i := 0; i < 32; i++ {
		s[i] = tmp[i] ^ ((^tmp[(i+1)%32]) & tmp[(i+2)%32])
	}
}

// Layer 4: NTT Butterfly Mixing
func nttButterflyHalf(s *[lanes]uint32, offset int) {
	step := 8
	for step >= 1 {
		group := 0
		for group < 16 {
			for j := 0; j < step; j++ {
				idx1 := offset + group + j
				idx2 := offset + group + j + step
				omegaIdx := (j * (16 / (step * 2))) % 16
				temp := uint32(uint64(s[idx2]) * uint64(omega[omegaIdx]) & mask32)
				s[idx2] = s[idx1] - temp
				s[idx1] = s[idx1] + temp
			}
			group += step * 2
		}
		step /= 2
	}
}

func applyNTTButterfly(s *[lanes]uint32) {
	nttButterflyHalf(s, 0)
	nttButterflyHalf(s, 16)
	for i := 0; i < 16; i++ {
		a := s[i]
		b := s[16+i]
		s[i] = a ^ rotl32(b, 11)
		s[16+i] = b ^ rotl32(a, 23)
	}
}

// Layer 5: Round Key Injection
func applyRoundKey(s *[lanes]uint32, rk *[lanes]uint32) {
	for i := 0; i < 32; i++ {
		s[i] ^= rk[i]
	}
}

// ---------- permutation ------------------------------------------------------

func permutation(s *[lanes]uint32, rounds int, roundKeys [][lanes]uint32) {
	nrk := len(roundKeys)
	for i := 0; i < rounds; i++ {
		applyRoundConstant(s, i)
		applyTheta(s)
		applyChi(s)
		applyNTTButterfly(s)
		applyRoundKey(s, &roundKeys[i%nrk])
	}
}

func bootstrapPermutation(s *[lanes]uint32, rounds int) {
	for i := 0; i < rounds; i++ {
		applyRoundConstant(s, i)
		applyTheta(s)
		applyChi(s)
		applyNTTButterfly(s)
	}
}

// ---------- key schedule -----------------------------------------------------

func keySchedule(masterKey []byte) [][lanes]uint32 {
	// Reverse key
	revKey := make([]byte, KeySize)
	for i := 0; i < KeySize; i++ {
		revKey[i] = masterKey[KeySize-1-i]
	}
	// Concatenate: key || reversed_key → 128 bytes → state
	combined := make([]byte, StateSize)
	copy(combined[:KeySize], masterKey)
	copy(combined[KeySize:], revKey)
	c := stateFromBytes(combined)

	roundKeys := make([][lanes]uint32, 0, 24)
	for r := 0; r < 24; r++ {
		bootstrapPermutation(&c, kdfRounds)
		var rk [lanes]uint32
		copy(rk[:], c[:])
		roundKeys = append(roundKeys, rk)
		c[0] ^= uint32(r)
		c[1] ^= domainKS
	}
	return roundKeys
}

// ---------- state initialisation ---------------------------------------------

func initState(key, nonce []byte) [lanes]uint32 {
	// IV(8 bytes LE) + key(64) + nonce(32) + zeros(24) = 128 bytes
	buf := make([]byte, StateSize)
	binary.LittleEndian.PutUint64(buf[0:8], c512IV)
	copy(buf[8:72], key)
	copy(buf[72:104], nonce)
	// remaining 24 bytes are zero
	return stateFromBytes(buf)
}

// ---------- padding ----------------------------------------------------------

func pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	out[len(data)] = 0x80
	// rest is already zero
	return out
}

// ---------- XOR / keystream helpers ------------------------------------------

func xorBlockIntoState(s *[lanes]uint32, block []byte, offset int) {
	for i := 0; i < 16; i++ {
		v := binary.LittleEndian.Uint32(block[offset+i*4:])
		s[i] ^= v
	}
}

func extractKeystream(s *[lanes]uint32, length int) []byte {
	rate := make([]byte, RateSize)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(rate[i*4:], s[i])
	}
	return rate[:length]
}

// ---------- AEAD Encrypt -----------------------------------------------------

// Encrypt encrypts plaintext with C512 v2.0 AEAD.
// Returns ciphertext || tag (len(plaintext) + TagSize bytes).
func Encrypt(key, nonce, aad, plaintext []byte) ([]byte, error) {
	if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }
 if len(key) != KeySize {
		return nil, fmt.Errorf("c512: key must be %d bytes", KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("c512: nonce must be %d bytes", NonceSize)
	}

	roundKeys := keySchedule(key)
	state := initState(key, nonce)
	permutation(&state, roundsA, roundKeys)

	// Absorb AAD (Phase-B rounds)
	if len(aad) > 0 {
		aadPadded := pad(aad, RateSize)
		nBlocks := len(aadPadded) / RateSize
		for i := 0; i < nBlocks; i++ {
			xorBlockIntoState(&state, aadPadded, i*RateSize)
			permutation(&state, roundsB, roundKeys)
		}
	}

	// Domain separation: AAD -> plaintext
	state[31] ^= domainSEP

	// Absorb plaintext / emit ciphertext
	ptLen := len(plaintext)
	fullBlocks := ptLen / RateSize
	remaining := ptLen % RateSize
	ciphertext := make([]byte, 0, ptLen+TagSize)

	for i := 0; i < fullBlocks; i++ {
		keystream := extractKeystream(&state, RateSize)
		off := i * RateSize
		ct := make([]byte, RateSize)
		for j := 0; j < RateSize; j++ {
			ct[j] = keystream[j] ^ plaintext[off+j]
		}
		ciphertext = append(ciphertext, ct...)
		// Absorb plaintext block
		absorb := make([]byte, RateSize)
		copy(absorb, plaintext[off:off+RateSize])
		xorBlockIntoState(&state, absorb, 0)
		permutation(&state, roundsB, roundKeys)
	}

	// Last (partial) block
	lastBlock := make([]byte, RateSize)
	if remaining > 0 {
		off := fullBlocks * RateSize
		keystream := extractKeystream(&state, remaining)
		for j := 0; j < remaining; j++ {
			ciphertext = append(ciphertext, keystream[j]^plaintext[off+j])
			lastBlock[j] = plaintext[off+j]
		}
	}
	lastBlock[remaining] = 0x80
	xorBlockIntoState(&state, lastBlock, 0)
	permutation(&state, roundsB, roundKeys)

	// Finalize
	permutation(&state, roundsA, roundKeys)

	// Tag derivation
	state[31] ^= domainTAG
	permutation(&state, roundsA, roundKeys)

	tag := make([]byte, TagSize)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(tag[i*4:], state[i])
	}

	ciphertext = append(ciphertext, tag...)
	return ciphertext, nil
}

// ---------- AEAD Decrypt -----------------------------------------------------

// Decrypt decrypts data (ciphertext || tag) with C512 v2.0 AEAD.
// Returns plaintext or an error on authentication failure.
func Decrypt(key, nonce, aad, data []byte) ([]byte, error) {
	if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }
 if len(key) != KeySize {
		return nil, fmt.Errorf("c512: key must be %d bytes", KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("c512: nonce must be %d bytes", NonceSize)
	}
	if len(data) < TagSize {
		return nil, ErrDataShort
	}

	ct := data[:len(data)-TagSize]
	tag := data[len(data)-TagSize:]

	roundKeys := keySchedule(key)
	state := initState(key, nonce)
	permutation(&state, roundsA, roundKeys)

	// Absorb AAD (Phase-B rounds)
	if len(aad) > 0 {
		aadPadded := pad(aad, RateSize)
		nBlocks := len(aadPadded) / RateSize
		for i := 0; i < nBlocks; i++ {
			xorBlockIntoState(&state, aadPadded, i*RateSize)
			permutation(&state, roundsB, roundKeys)
		}
	}

	// Domain separation
	state[31] ^= domainSEP

	// Decrypt ciphertext
	ctLen := len(ct)
	fullBlocks := ctLen / RateSize
	remaining := ctLen % RateSize
	plaintext := make([]byte, 0, ctLen)

	for i := 0; i < fullBlocks; i++ {
		keystream := extractKeystream(&state, RateSize)
		off := i * RateSize
		absorb := make([]byte, RateSize)
		for j := 0; j < RateSize; j++ {
			pb := keystream[j] ^ ct[off+j]
			plaintext = append(plaintext, pb)
			absorb[j] = pb
		}
		xorBlockIntoState(&state, absorb, 0)
		permutation(&state, roundsB, roundKeys)
	}

	// Last (partial) block
	lastBlock := make([]byte, RateSize)
	if remaining > 0 {
		off := fullBlocks * RateSize
		keystream := extractKeystream(&state, remaining)
		for j := 0; j < remaining; j++ {
			pb := keystream[j] ^ ct[off+j]
			plaintext = append(plaintext, pb)
			lastBlock[j] = pb
		}
	}
	lastBlock[remaining] = 0x80
	xorBlockIntoState(&state, lastBlock, 0)
	permutation(&state, roundsB, roundKeys)

	// Finalize
	permutation(&state, roundsA, roundKeys)

	// Tag verification
	state[31] ^= domainTAG
	permutation(&state, roundsA, roundKeys)

	expectedTag := make([]byte, TagSize)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(expectedTag[i*4:], state[i])
	}

	if subtle.ConstantTimeCompare(expectedTag, tag) != 1 {
		return nil, ErrAuthFailed
	}

	return plaintext, nil
}

// ---------- XOF Mode ---------------------------------------------------------

// XOF derives arbitrary-length output from key + context.
// Usable as KDF, PRF, or stream cipher primitive.
func XOF(key, context []byte, outputLength int) ([]byte, error) {
	if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }
 if len(key) != KeySize {
		return nil, fmt.Errorf("c512: key must be %d bytes", KeySize)
	}
	if outputLength < 0 {
		return nil, fmt.Errorf("c512: outputLength must be non-negative")
	}

	roundKeys := keySchedule(key)

	var state [lanes]uint32
	for i := 0; i < 16; i++ {
		state[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[31] ^= domainXOF

	permutation(&state, roundsA, roundKeys)

	// Absorb context
	if len(context) > 0 {
		ctxPadded := pad(context, RateSize)
		nBlocks := len(ctxPadded) / RateSize
		for i := 0; i < nBlocks; i++ {
			xorBlockIntoState(&state, ctxPadded, i*RateSize)
			permutation(&state, roundsB, roundKeys)
		}
	}

	// Squeeze domain separator
	state[31] ^= domainSQZ
	permutation(&state, roundsA, roundKeys)

	// Squeeze output
	output := make([]byte, 0, outputLength)
	for len(output) < outputLength {
		needed := outputLength - len(output)
		if needed > RateSize {
			needed = RateSize
		}
		output = append(output, extractKeystream(&state, needed)...)
		if len(output) < outputLength {
			permutation(&state, roundsB, roundKeys)
		}
	}

	return output[:outputLength], nil
}

// ---------- SIV Mode ---------------------------------------------------------

func sivDeriveNonce(key, aad, plaintext []byte) ([]byte, error) {
	// Build SIV input: LE64(len(aad)) || aad || LE64(len(plaintext)) || plaintext
	sivInput := make([]byte, 8+len(aad)+8+len(plaintext))
	binary.LittleEndian.PutUint64(sivInput[0:8], uint64(len(aad)))
	copy(sivInput[8:], aad)
	binary.LittleEndian.PutUint64(sivInput[8+len(aad):], uint64(len(plaintext)))
	copy(sivInput[8+len(aad)+8:], plaintext)

	roundKeys := keySchedule(key)

	var state [lanes]uint32
	for i := 0; i < 16; i++ {
		state[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[31] ^= domainSIV

	permutation(&state, roundsA, roundKeys)

	if len(sivInput) > 0 {
		sivPadded := pad(sivInput, RateSize)
		nBlocks := len(sivPadded) / RateSize
		for i := 0; i < nBlocks; i++ {
			xorBlockIntoState(&state, sivPadded, i*RateSize)
			permutation(&state, roundsB, roundKeys)
		}
	}

	state[31] ^= domainSQZ
	permutation(&state, roundsA, roundKeys)

	nonce := make([]byte, NonceSize)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(nonce[i*4:], state[i])
	}
	return nonce, nil
}

// SIVEncrypt performs misuse-resistant AEAD encryption.
// Returns: synthetic_nonce(32) || ciphertext || tag(32).
func SIVEncrypt(key, aad, plaintext []byte) ([]byte, error) {
	if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }
 if len(key) != KeySize {
		return nil, fmt.Errorf("c512: key must be %d bytes", KeySize)
	}
	nonce, err := sivDeriveNonce(key, aad, plaintext)
	if err != nil {
		return nil, err
	}
	ctTag, err := Encrypt(key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, NonceSize+len(ctTag))
	result = append(result, nonce...)
	result = append(result, ctTag...)
	return result, nil
}

// SIVDecrypt performs misuse-resistant AEAD decryption.
// Input: synthetic_nonce(32) || ciphertext || tag(32).
func SIVDecrypt(key, aad, data []byte) ([]byte, error) {
	if os.Getenv("ALB_C512_EXPERIMENTAL") != "1" { return nil, fmt.Errorf("C512 is research only; explicit experimental opt-in required") }
 if len(key) != KeySize {
		return nil, fmt.Errorf("c512: key must be %d bytes", KeySize)
	}
	if len(data) < NonceSize+TagSize {
		return nil, ErrDataShort
	}

	nonce := data[:NonceSize]
	ctTag := data[NonceSize:]

	plaintext, err := Decrypt(key, nonce, aad, ctTag)
	if err != nil {
		return nil, err
	}

	expectedNonce, err := sivDeriveNonce(key, aad, plaintext)
	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(nonce, expectedNonce) != 1 {
		return nil, errors.New("c512: SIV synthetic nonce verification failed")
	}

	return plaintext, nil
}

// ---------- Convenience wrappers ---------------------------------------------

// EncryptWithNonce encrypts with an auto-generated random nonce.
// Returns: nonce(32) || ciphertext || tag(32).
func EncryptWithNonce(key, aad, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("c512: failed to generate nonce: %w", err)
	}
	ctTag, err := Encrypt(key, nonce, aad, plaintext)
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, NonceSize+len(ctTag))
	result = append(result, nonce...)
	result = append(result, ctTag...)
	return result, nil
}

// DecryptWithNonce decrypts data that starts with a 32-byte nonce prefix.
func DecryptWithNonce(key, aad, data []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, ErrDataShort
	}
	nonce := data[:NonceSize]
	inner := data[NonceSize:]
	return Decrypt(key, nonce, aad, inner)
}
