package albpkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	pemBegin = "-----BEGIN ALBPKG PUBLIC IDENTITY-----"
	pemEnd   = "-----END ALBPKG PUBLIC IDENTITY-----"

	// MinPassphraseLen is the shortest passphrase this port will accept.
	MinPassphraseLen = 8
)

// PassphraseProvider supplies a passphrase. It is never given argv content.
type PassphraseProvider func(prompt string) (string, error)

// ---- Fingerprints --------------------------------------------------------

// FingerprintOf returns SHA-256 over a canonical public identity.
func FingerprintOf(pubid []byte) []byte {
	sum := sha256.Sum256(pubid)
	return sum[:]
}

// FormatFingerprint renders 64 lowercase hex characters in eight
// dash-separated groups of eight.
func FormatFingerprint(fpr []byte) (string, error) {
	if len(fpr) != FprLen {
		return "", formatErrorf("fingerprint must be 32 bytes")
	}
	encoded := hex.EncodeToString(fpr)
	groups := make([]string, 0, 8)
	for i := 0; i < 64; i += 8 {
		groups = append(groups, encoded[i:i+8])
	}
	return strings.Join(groups, "-"), nil
}

var fingerprintStrip = regexp.MustCompile(`[-\s:]`)

// ParseFingerprint accepts grouped or ungrouped hex. The full 256 bits are
// required: truncated fingerprints are never accepted.
func ParseFingerprint(text string) ([]byte, error) {
	cleaned := fingerprintStrip.ReplaceAllString(strings.ToLower(strings.TrimSpace(text)), "")
	if len(cleaned) != 64 {
		return nil, formatErrorf(
			"a fingerprint is 64 hex characters; truncated fingerprints are not accepted")
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, formatErrorf("fingerprint is not valid hex")
	}
	return raw, nil
}

// FingerprintsEqual compares two fingerprints in constant time.
func FingerprintsEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return constantTimeBytesEqual(a, b)
}

// ---- Canonical public identity ------------------------------------------

// EncodePubID builds the canonical public identity (FORMAT.md 2.1).
func EncodePubID(kemPub, sigPub []byte) ([]byte, error) {
	if len(kemPub) != KemPubLen {
		return nil, formatErrorf("ML-KEM-768 public key has the wrong length")
	}
	if len(sigPub) != SigPubLen {
		return nil, formatErrorf("ML-DSA-65 public key has the wrong length")
	}
	out := make([]byte, 0, PubIDLen)
	out = append(out, PubIDMagic...)
	out = append(out, encU16(SuiteID)...)
	out = append(out, encU16(KemPubLen)...)
	out = append(out, kemPub...)
	out = append(out, encU16(SigPubLen)...)
	out = append(out, sigPub...)
	return out, nil
}

// DecodePubID strictly decodes a canonical public identity.
func DecodePubID(data []byte) (kemPub, sigPub []byte, err error) {
	if len(data) != PubIDLen {
		return nil, nil, formatErrorf(
			"public identity must be exactly %d bytes, got %d", PubIDLen, len(data))
	}
	r := newByteReader(data, "public identity")
	if err := r.expect(PubIDMagic, "public identity magic"); err != nil {
		return nil, nil, err
	}
	suiteID, err := r.u16("suite id")
	if err != nil {
		return nil, nil, err
	}
	if suiteID != SuiteID {
		return nil, nil, unsupportedErrorf("unsupported suite id 0x%04x", suiteID)
	}
	kemLen, err := r.u16("kem public key length")
	if err != nil {
		return nil, nil, err
	}
	if kemLen != KemPubLen {
		return nil, nil, formatErrorf("noncanonical ML-KEM public key length")
	}
	kemRaw, err := r.take(kemLen, "kem public key")
	if err != nil {
		return nil, nil, err
	}
	sigLen, err := r.u16("signature public key length")
	if err != nil {
		return nil, nil, err
	}
	if sigLen != SigPubLen {
		return nil, nil, formatErrorf("noncanonical ML-DSA public key length")
	}
	sigRaw, err := r.take(sigLen, "signature public key")
	if err != nil {
		return nil, nil, err
	}
	if err := r.finish(); err != nil {
		return nil, nil, err
	}
	return bytes.Clone(kemRaw), bytes.Clone(sigRaw), nil
}

// PublicIdentity is a contact's public half: both keys plus the fingerprint.
type PublicIdentity struct {
	KemPublicBytes []byte
	SigPublicBytes []byte
}

// PubID returns the canonical encoding.
func (p *PublicIdentity) PubID() []byte {
	out, err := EncodePubID(p.KemPublicBytes, p.SigPublicBytes)
	if err != nil {
		return nil
	}
	return out
}

// Fingerprint returns SHA-256 over the canonical encoding.
func (p *PublicIdentity) Fingerprint() []byte {
	return FingerprintOf(p.PubID())
}

// FingerprintText returns the grouped display form.
func (p *PublicIdentity) FingerprintText() string {
	text, _ := FormatFingerprint(p.Fingerprint())
	return text
}

// KemKey rebuilds the ML-KEM encapsulation key from the wire bytes.
func (p *PublicIdentity) KemKey() (*mlkem.EncapsulationKey768, error) {
	key, err := mlkem.NewEncapsulationKey768(p.KemPublicBytes)
	if err != nil {
		return nil, formatErrorf("stored ML-KEM public key is not a valid key")
	}
	return key, nil
}

// SigKey rebuilds the ML-DSA verification key from the wire bytes.
func (p *PublicIdentity) SigKey() (*mldsa65.PublicKey, error) {
	var key mldsa65.PublicKey
	if err := key.UnmarshalBinary(p.SigPublicBytes); err != nil {
		return nil, formatErrorf("stored ML-DSA public key is not a valid key")
	}
	return &key, nil
}

// PublicIdentityFromPubID decodes and validates a canonical public identity.
func PublicIdentityFromPubID(data []byte) (*PublicIdentity, error) {
	kemPub, sigPub, err := DecodePubID(data)
	if err != nil {
		return nil, err
	}
	return &PublicIdentity{KemPublicBytes: kemPub, SigPublicBytes: sigPub}, nil
}

// ToArmored renders the shareable public identity file (FORMAT.md 2.3).
func (p *PublicIdentity) ToArmored() string {
	body := base64.StdEncoding.EncodeToString(p.PubID())
	var wrapped strings.Builder
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		wrapped.WriteString(body[i:end])
		wrapped.WriteString("\n")
	}
	return pemBegin + "\n" +
		"suite: " + SuiteName + "\n" +
		"fingerprint: " + hex.EncodeToString(p.Fingerprint()) + "\n" +
		wrapped.String() +
		pemEnd + "\n"
}

var base64Line = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

// PublicIdentityFromArmored parses a public identity file and requires its
// fingerprint header to match the keys it carries.
func PublicIdentityFromArmored(text string) (*PublicIdentity, error) {
	var lines []string
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	if len(lines) < 2 || lines[0] != pemBegin || lines[len(lines)-1] != pemEnd {
		return nil, formatErrorf("not an ALBPKG public identity file")
	}

	declared := ""
	var body strings.Builder
	for _, line := range lines[1 : len(lines)-1] {
		lowered := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lowered, "suite:"):
			if strings.TrimSpace(line[strings.Index(line, ":")+1:]) != SuiteName {
				return nil, unsupportedErrorf("unsupported suite in public identity file")
			}
		case strings.HasPrefix(lowered, "fingerprint:"):
			if declared != "" {
				return nil, formatErrorf("duplicate fingerprint header")
			}
			declared = strings.ToLower(strings.TrimSpace(line[strings.Index(line, ":")+1:]))
		case strings.Contains(line, ":") && !base64Line.MatchString(line):
			return nil, formatErrorf("unknown header in public identity file")
		default:
			body.WriteString(line)
		}
	}
	if declared == "" {
		return nil, formatErrorf("public identity file has no fingerprint header")
	}

	raw, err := base64.StdEncoding.DecodeString(body.String())
	if err != nil {
		return nil, formatErrorf("public identity body is not valid base64")
	}
	identity, err := PublicIdentityFromPubID(raw)
	if err != nil {
		return nil, err
	}
	expected, err := ParseFingerprint(declared)
	if err != nil {
		return nil, err
	}
	if !FingerprintsEqual(identity.Fingerprint(), expected) {
		return nil, formatErrorf(
			"public identity fingerprint header does not match the encoded keys")
	}
	return identity, nil
}

// ---- Private identity ----------------------------------------------------

// Identity holds both private keys, plus the seeds they were built from so the
// file can be rewritten without regenerating anything.
type Identity struct {
	KemPrivate *mlkem.DecapsulationKey768
	SigPrivate *mldsa65.PrivateKey

	kemSeed []byte
	sigSeed []byte
}

// Public returns the public half of this identity.
func (i *Identity) Public() *PublicIdentity {
	sigPub, _ := i.SigPrivate.Public().(*mldsa65.PublicKey)
	sigBytes, _ := sigPub.MarshalBinary()
	return &PublicIdentity{
		KemPublicBytes: i.KemPrivate.EncapsulationKey().Bytes(),
		SigPublicBytes: sigBytes,
	}
}

// Fingerprint returns this identity's fingerprint.
func (i *Identity) Fingerprint() []byte { return i.Public().Fingerprint() }

// GenerateIdentity creates a fresh, independent encryption key and signing key.
func GenerateIdentity() (*Identity, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}

	kemSeed := make([]byte, KemSeedLen)
	if _, err := rand.Read(kemSeed); err != nil {
		return nil, wrapError(CategoryIO, err, "could not read from the system CSPRNG")
	}
	sigSeed := make([]byte, SigSeedLen)
	if _, err := rand.Read(sigSeed); err != nil {
		return nil, wrapError(CategoryIO, err, "could not read from the system CSPRNG")
	}
	return identityFromSeeds(kemSeed, sigSeed)
}

func identityFromSeeds(kemSeed, sigSeed []byte) (*Identity, error) {
	if len(kemSeed) != KemSeedLen {
		return nil, formatErrorf("ML-KEM seed must be %d bytes", KemSeedLen)
	}
	if len(sigSeed) != SigSeedLen {
		return nil, formatErrorf("ML-DSA seed must be %d bytes", SigSeedLen)
	}

	kemPrivate, err := mlkem.NewDecapsulationKey768(kemSeed)
	if err != nil {
		return nil, formatErrorf("ML-KEM seed does not expand to a valid key")
	}
	var seed32 [mldsa65.SeedSize]byte
	copy(seed32[:], sigSeed)
	_, sigPrivate := mldsa65.NewKeyFromSeed(&seed32)
	wipe(seed32[:])

	return &Identity{
		KemPrivate: kemPrivate,
		SigPrivate: sigPrivate,
		kemSeed:    bytes.Clone(kemSeed),
		sigSeed:    bytes.Clone(sigSeed),
	}, nil
}

// Close wipes the seeds this identity is holding.
func (i *Identity) Close() {
	wipe(i.kemSeed)
	wipe(i.sigSeed)
}

func deriveKek(passphrase, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, AeadKeyLen)
	if err != nil {
		return nil, wrapError(CategoryPassphrase, err, "key derivation failed")
	}
	return key, nil
}

func encodeSeeds(kemSeed, sigSeed []byte) []byte {
	out := make([]byte, 0, 2+len(kemSeed)+2+len(sigSeed))
	out = append(out, encU16(len(kemSeed))...)
	out = append(out, kemSeed...)
	out = append(out, encU16(len(sigSeed))...)
	out = append(out, sigSeed...)
	return out
}

func decodeSeeds(blob []byte) (kemSeed, sigSeed []byte, err error) {
	r := newByteReader(blob, "identity seeds")
	kemLen, err := r.u16("kem seed length")
	if err != nil {
		return nil, nil, err
	}
	if kemLen != KemSeedLen {
		return nil, nil, formatErrorf("noncanonical ML-KEM seed length")
	}
	kemRaw, err := r.take(kemLen, "kem seed")
	if err != nil {
		return nil, nil, err
	}
	sigLen, err := r.u16("signing seed length")
	if err != nil {
		return nil, nil, err
	}
	if sigLen != SigSeedLen {
		return nil, nil, formatErrorf("noncanonical ML-DSA seed length")
	}
	sigRaw, err := r.take(sigLen, "signing seed")
	if err != nil {
		return nil, nil, err
	}
	if err := r.finish(); err != nil {
		return nil, nil, err
	}
	return bytes.Clone(kemRaw), bytes.Clone(sigRaw), nil
}

func resolvePassphrase(provider PassphraseProvider, prompt string, confirm bool) ([]byte, error) {
	if provider == nil {
		return nil, passphraseErrorf("no passphrase source was supplied")
	}
	text, err := provider(prompt)
	if err != nil {
		return nil, err
	}
	if text == "" {
		return nil, passphraseErrorf("an empty passphrase is not accepted")
	}
	if len(text) < MinPassphraseLen {
		return nil, passphraseErrorf(
			"passphrase must be at least %d characters", MinPassphraseLen)
	}
	if confirm {
		again, err := provider(prompt + " (confirm)")
		if err != nil {
			return nil, err
		}
		if again != text {
			return nil, passphraseErrorf("passphrases did not match")
		}
	}
	return []byte(text), nil
}

// SaveIdentity writes the passphrase-encrypted private identity with
// owner-only permissions.
//
// A fresh salt is drawn on every write, which is what makes the fixed all-zero
// GCM nonce safe: the key encryption key is never reused.
func saveLegacyIdentity(identity *Identity, path string, provider PassphraseProvider,
	overwrite bool, iterations int) error {

	if iterations == 0 {
		iterations = KdfIterations
	}
	if iterations < KdfMinIterations || iterations > KdfMaxIterations {
		return limitErrorf("iteration count must be between %d and %d",
			KdfMinIterations, KdfMaxIterations)
	}

	secret, err := resolvePassphrase(provider,
		"Passphrase for "+filepath.Base(path), true)
	if err != nil {
		return err
	}
	defer wipe(secret)

	pubid := identity.Public().PubID()
	salt := make([]byte, KdfSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return wrapError(CategoryIO, err, "could not read from the system CSPRNG")
	}

	prefix := make([]byte, 0, 8+2+2+4+KdfSaltLen+4+len(pubid))
	prefix = append(prefix, SKFileMagic...)
	prefix = append(prefix, encU16(SuiteID)...)
	prefix = append(prefix, encU16(KdfPBKDF2SHA256)...)
	prefix = append(prefix, encU32(iterations)...)
	prefix = append(prefix, salt...)
	prefix = append(prefix, encU32(len(pubid))...)
	prefix = append(prefix, pubid...)

	seeds := encodeSeeds(identity.kemSeed, identity.sigSeed)
	defer wipe(seeds)

	kek, err := deriveKek(secret, salt, iterations)
	if err != nil {
		return err
	}
	defer wipe(kek)

	aead, err := newGCM(kek)
	if err != nil {
		return err
	}
	sealed := aead.Seal(nil, AeadNonce, seeds, prefix)

	blob := make([]byte, 0, len(prefix)+4+len(sealed))
	blob = append(blob, prefix...)
	blob = append(blob, encU32(len(sealed))...)
	blob = append(blob, sealed...)

	if err := withAtomicOutput(path, overwrite, func(file *os.File) error {
		return writeAll(file, blob)
	}); err != nil {
		return err
	}
	return restrictPermissions(path)
}

// LoadIdentity loads and decrypts a private identity file, validating it
// strictly.
func loadLegacyIdentity(path string, provider PassphraseProvider) (*Identity, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot open identity file")
	}
	defer file.Close()
	blob, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot read identity file %s",
			filepath.Base(path))
	}
	if len(blob) > 65536 {
		return nil, limitErrorf("identity file exceeds 64 KiB")
	}
	if !permissionsAreOwnerOnly(path) {
		return nil, ioErrorf(
			"identity file %s is readable by others; fix its permissions before use",
			filepath.Base(path))
	}

	r := newByteReader(blob, "identity file")
	if err := r.expect(SKFileMagic, "identity file magic"); err != nil {
		return nil, err
	}
	suiteID, err := r.u16("suite id")
	if err != nil {
		return nil, err
	}
	if suiteID != SuiteID {
		return nil, unsupportedErrorf("unsupported suite id 0x%04x", suiteID)
	}
	kdfID, err := r.u16("kdf id")
	if err != nil {
		return nil, err
	}
	if kdfID != KdfPBKDF2SHA256 {
		return nil, unsupportedErrorf("unsupported key derivation function 0x%04x", kdfID)
	}
	iterations, err := r.u32("iteration count")
	if err != nil {
		return nil, err
	}
	if iterations < KdfMinIterations || iterations > KdfMaxIterations {
		return nil, limitErrorf(
			"iteration count %d is outside the permitted range [%d, %d]",
			iterations, KdfMinIterations, KdfMaxIterations)
	}
	salt, err := r.take(KdfSaltLen, "salt")
	if err != nil {
		return nil, err
	}
	pubidLen, err := r.u32("public identity length")
	if err != nil {
		return nil, err
	}
	if pubidLen != PubIDLen {
		return nil, formatErrorf("noncanonical public identity length in identity file")
	}
	pubid, err := r.take(int(pubidLen), "public identity")
	if err != nil {
		return nil, err
	}
	storedPublic, err := PublicIdentityFromPubID(pubid)
	if err != nil {
		return nil, err
	}

	prefixLen := r.offset()
	sealedLen, err := r.u32("sealed length")
	if err != nil {
		return nil, err
	}
	if sealedLen == 0 || sealedLen > maxSealedSeedLen {
		return nil, limitErrorf("implausible sealed seed length %d", sealedLen)
	}
	sealed, err := r.take(int(sealedLen), "sealed seeds")
	if err != nil {
		return nil, err
	}
	if err := r.finish(); err != nil {
		return nil, err
	}

	secret, err := resolvePassphrase(provider,
		"Passphrase for "+filepath.Base(path), false)
	if err != nil {
		return nil, err
	}
	defer wipe(secret)

	kek, err := deriveKek(secret, salt, int(iterations))
	if err != nil {
		return nil, err
	}
	defer wipe(kek)

	aead, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	seeds, err := aead.Open(nil, AeadNonce, sealed, blob[:prefixLen])
	if err != nil {
		// A wrong passphrase and a tampered file are indistinguishable here,
		// which is the correct behaviour: both mean "do not proceed".
		return nil, passphraseErrorf(
			"could not decrypt the identity file; the passphrase is wrong or " +
				"the file has been altered")
	}
	defer wipe(seeds)

	kemSeed, sigSeed, err := decodeSeeds(seeds)
	if err != nil {
		return nil, err
	}
	defer wipe(kemSeed)
	defer wipe(sigSeed)

	identity, err := identityFromSeeds(kemSeed, sigSeed)
	if err != nil {
		return nil, err
	}
	if !FingerprintsEqual(identity.Fingerprint(), storedPublic.Fingerprint()) {
		identity.Close()
		return nil, authErrorf(
			"identity file seeds do not reproduce its stored public identity")
	}
	return identity, nil
}

// SaveIdentity stores the independent keys as standard encrypted PKCS#8
// objects in one canonical PEM identity file.
func SaveIdentity(identity *Identity, path string, provider PassphraseProvider,
	overwrite bool, iterations int) error {
	if iterations == 0 {
		iterations = pkcs8DefaultIterations
	}
	secret, err := resolvePassphrase(provider, "Passphrase for "+filepath.Base(path), true)
	if err != nil {
		return err
	}
	defer wipe(secret)
	kemPlain := encodePlainPKCS8(identity.kemSeed, oidMLKEM768)
	sigPlain := encodePlainPKCS8(identity.sigSeed, oidMLDSA65)
	defer wipe(kemPlain)
	defer wipe(sigPlain)
	kemEncrypted, err := encryptPKCS8(kemPlain, secret, iterations)
	if err != nil {
		return err
	}
	sigEncrypted, err := encryptPKCS8(sigPlain, secret, iterations)
	if err != nil {
		return err
	}
	blob := encodeIdentityPEM(kemEncrypted, sigEncrypted)
	if err := withAtomicOutput(path, overwrite, func(file *os.File) error {
		return writeAll(file, blob)
	}); err != nil {
		return err
	}
	return restrictPermissions(path)
}

// LoadIdentity reads only the canonical encrypted-PKCS#8 identity format.
// Legacy ALBPKSK2 requires the explicit MigrateLegacyIdentity entry point.
func LoadIdentity(path string, provider PassphraseProvider) (*Identity, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot open identity file")
	}
	defer file.Close()
	blob, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot read identity file")
	}
	if len(blob) > 65536 {
		return nil, limitErrorf("identity file exceeds 64 KiB")
	}
	if !permissionsAreOwnerOnly(path) {
		return nil, ioErrorf("identity file %s is readable by others; fix its permissions before use", filepath.Base(path))
	}
	kemEncrypted, sigEncrypted, err := parseIdentityPEM(blob)
	if err != nil {
		return nil, err
	}
	secret, err := resolvePassphrase(provider, "Passphrase for "+filepath.Base(path), false)
	if err != nil {
		return nil, err
	}
	defer wipe(secret)
	kemPlain, err := decryptPKCS8(kemEncrypted, secret)
	if err != nil {
		return nil, err
	}
	defer wipe(kemPlain)
	sigPlain, err := decryptPKCS8(sigEncrypted, secret)
	if err != nil {
		return nil, err
	}
	defer wipe(sigPlain)
	kemSeed, err := parsePlainPKCS8(kemPlain, oidMLKEM768, KemSeedLen)
	if err != nil {
		return nil, err
	}
	defer wipe(kemSeed)
	sigSeed, err := parsePlainPKCS8(sigPlain, oidMLDSA65, SigSeedLen)
	if err != nil {
		return nil, err
	}
	defer wipe(sigSeed)
	return identityFromSeeds(kemSeed, sigSeed)
}

// MigrateLegacyIdentity explicitly converts ALBPKSK2 and retains the source.
// Normal loading never falls back to this parser.
func MigrateLegacyIdentity(source, target string, provider PassphraseProvider, overwrite bool) (*Identity, error) {
	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		return nil, err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	if sourceAbs == targetAbs {
		return nil, ioErrorf("legacy source and PKCS#8 destination must be different paths")
	}
	identity, err := loadLegacyIdentity(source, provider)
	if err != nil {
		return nil, err
	}
	if err = SaveIdentity(identity, target, provider, overwrite, 0); err != nil {
		identity.Close()
		return nil, err
	}
	return identity, nil
}

// ExportPublicIdentity writes the armored public identity and returns its
// fingerprint text.
func ExportPublicIdentity(public *PublicIdentity, path string, overwrite bool) (string, error) {
	armored := []byte(public.ToArmored())
	if err := withAtomicOutput(path, overwrite, func(file *os.File) error {
		return writeAll(file, armored)
	}); err != nil {
		return "", err
	}
	return public.FingerprintText(), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapError(CategoryProvider, err, "AES-256 is unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapError(CategoryProvider, err, "AES-256-GCM is unavailable")
	}
	return aead, nil
}
