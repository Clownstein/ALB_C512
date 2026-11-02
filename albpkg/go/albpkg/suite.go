package albpkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"encoding/binary"
	"math"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Suite constants (FORMAT.md section 1). None of these is configurable at
// runtime: a build either supports ALBPKG-1 in full or refuses to run.
const (
	SuiteID       = 0x0001
	SuiteName     = "ALBPKG-1"
	FormatVersion = 1

	KemPubLen  = 1184
	KemCtLen   = 1088
	KemSSLen   = 32
	KemSeedLen = 64
	SigPubLen  = 1952
	SigLen     = 3309
	SigSeedLen = 32

	AeadKeyLen   = 32
	AeadTagLen   = 16
	AeadNonceLen = 12

	FprLen       = 32
	PackageIDLen = 16
)

// Magics.
var (
	PubIDMagic      = []byte("ALBPKID1")
	SKFileMagic     = []byte("ALBPKSK2")
	PackageMagic    = []byte("ALBPKG1\x00")
	SigTrailerMagic = []byte("ALBPKGSG")
)

// AeadNonce is the fixed all-zero GCM nonce. It is safe only because every key
// it is used with is derived once and never reused (FORMAT.md 3.2, 2.4).
var AeadNonce = make([]byte, AeadNonceLen)

// Derived lengths.
const (
	PubIDLen      = 8 + 2 + 2 + KemPubLen + 2 + SigPubLen // 3150
	HeaderLen     = 8 + 2 + 2 + 4 + 4 + 4 + FprLen*2 + PackageIDLen + 2 + KemCtLen
	SigTrailerLen = 4 + 8
)

// Private identity container (FORMAT.md 2.4).
const (
	KdfPBKDF2SHA256  = 0x0001
	KdfSaltLen       = 16
	KdfIterations    = 600_000
	KdfMinIterations = 600_000
	KdfMaxIterations = 10_000_000
)

// Domain separation strings (ASCII, no trailing NUL).
var (
	InfoMaster       = []byte("ALBPKG1 master v1")
	InfoChunk        = []byte("ALBPKG1 chunk v1")
	InfoComplete     = []byte("ALBPKG1 complete v1")
	AadChunkPrefix   = []byte("ALBPKG1-CHUNK")
	AadCompletePfx   = []byte("ALBPKG1-COMPLETE")
	SigContextPrefix = []byte("ALBPKG1-SIGV1")
)

// Limits (FORMAT.md section 4).
const (
	ChunkSize           = 1 << 20
	MaxPlaintext        = 1 << 40 // 1 TiB
	MaxChunks           = MaxPlaintext / ChunkSize
	ChunkFrameOverhead  = 1 + 4 + AeadTagLen
	CompletionLen       = 16 + AeadTagLen
	MaxPackageSize      = HeaderLen + MaxChunks*(ChunkSize+ChunkFrameOverhead) + CompletionLen + SigLen + SigTrailerLen
	MinPackageSize      = HeaderLen + ChunkFrameOverhead + CompletionLen + SigLen + SigTrailerLen
	maxSealedSeedLen    = 1 << 12
	maxContactFileBytes = 1 << 16
)

// CheckProvider fails closed unless every required primitive is available.
//
// A partial provider is treated as no provider: we never silently substitute a
// different algorithm.
func CheckProvider() error {
	var missing []string

	dk, err := mlkem.GenerateKey768()
	if err != nil || dk == nil {
		missing = append(missing, "ML-KEM-768")
	} else if len(dk.EncapsulationKey().Bytes()) != KemPubLen {
		missing = append(missing, "ML-KEM-768 (unexpected key size)")
	}

	if pub, _, err := mldsa65.GenerateKey(nil); err != nil || pub == nil {
		missing = append(missing, "ML-DSA-65")
	} else if mldsa65.SignatureSize != SigLen || mldsa65.PublicKeySize != SigPubLen {
		missing = append(missing, "ML-DSA-65 (unexpected sizes)")
	}

	block, err := aes.NewCipher(make([]byte, AeadKeyLen))
	if err != nil {
		missing = append(missing, "AES-256")
	} else if _, err := cipher.NewGCM(block); err != nil {
		missing = append(missing, "AES-256-GCM")
	}

	if len(missing) > 0 {
		return newError(CategoryProvider,
			"required algorithms unavailable from the cryptographic provider: %v", missing)
	}
	return nil
}

// ---- Canonical big-endian encoding with checked arithmetic ---------------

func putU16(dst []byte, v int) { binary.BigEndian.PutUint16(dst, uint16(v)) }
func putU32(dst []byte, v int) { binary.BigEndian.PutUint32(dst, uint32(v)) }

func encU8(v int) []byte {
	return []byte{byte(v)}
}

func encU16(v int) []byte {
	out := make([]byte, 2)
	putU16(out, v)
	return out
}

func encU32(v int) []byte {
	out := make([]byte, 4)
	putU32(out, v)
	return out
}

func encU64(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

// checkedAdd refuses to wrap. Go's int is 64-bit on the supported platforms,
// but the check is written to hold on a 32-bit build too.
func checkedAdd(a, b int, limit int64, what string) (int, error) {
	if a < 0 || b < 0 {
		return 0, limitErrorf("negative %s", what)
	}
	total := int64(a) + int64(b)
	if total > limit || total > math.MaxInt {
		return 0, limitErrorf("%s overflow: %d + %d exceeds %d", what, a, b, limit)
	}
	return int(total), nil
}

func init() {
	// Guard the compile-time constants against edit mistakes.
	if PubIDLen != 3150 {
		panic("albpkg: PubIDLen must be 3150")
	}
	if HeaderLen != 1194 {
		panic("albpkg: HeaderLen must be 1194")
	}
	if MaxChunks != 1048576 {
		panic("albpkg: MaxChunks must be 1048576")
	}
}
