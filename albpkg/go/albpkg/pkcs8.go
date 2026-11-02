package albpkg

// Strict PKCS#8/PBES2 profile. Cryptographic primitives come from Go's
// standard library; this file only implements the bounded ASN.1 DER framing
// required for PQ keys that crypto/x509 does not yet recognize.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const (
	pkcs8DefaultIterations = 600_000
	pkcs8MinIterations     = 600_000
	pkcs8MaxIterations     = 10_000_000
	pkcs8MaxDER            = 4096
)

var (
	oidPBES2       = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d}
	oidPBKDF2      = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c}
	oidHMACSHA256  = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09}
	oidAES256CBC   = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a}
	oidMLKEM768    = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02}
	oidMLDSA65     = []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}
	identityHeader = "ALBPKG PRIVATE IDENTITY 1\n"
	pkcs8Begin     = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
	pkcs8End       = "-----END ENCRYPTED PRIVATE KEY-----\n"
)

func derLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var raw [8]byte
	i := len(raw)
	for n > 0 {
		i--
		raw[i] = byte(n)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(raw)-i)}, raw[i:]...)
}
func derTLV(tag byte, value []byte) []byte {
	out := []byte{tag}
	out = append(out, derLength(len(value))...)
	return append(out, value...)
}
func derSeq(values ...[]byte) []byte { return derTLV(0x30, bytes.Join(values, nil)) }
func derOID(value []byte) []byte     { return derTLV(0x06, value) }
func derOctets(value []byte) []byte  { return derTLV(0x04, value) }
func derInteger(n int) []byte {
	var raw [8]byte
	i := len(raw)
	for n > 0 {
		i--
		raw[i] = byte(n)
		n >>= 8
	}
	if i == len(raw) {
		i--
		raw[i] = 0
	}
	if raw[i]&0x80 != 0 {
		i--
		raw[i] = 0
	}
	return derTLV(0x02, raw[i:])
}

type derReader struct {
	data   []byte
	offset int
	label  string
}

func newDER(data []byte, label string) *derReader { return &derReader{data: data, label: label} }
func (r *derReader) take(tag byte, field string) ([]byte, error) {
	if r.offset >= len(r.data) || r.data[r.offset] != tag {
		return nil, formatErrorf("noncanonical %s: expected %s", r.label, field)
	}
	r.offset++
	if r.offset >= len(r.data) {
		return nil, formatErrorf("truncated %s length", r.label)
	}
	first := r.data[r.offset]
	r.offset++
	size := 0
	if first < 0x80 {
		size = int(first)
	} else {
		count := int(first & 0x7f)
		if count == 0 || count > 4 || r.offset+count > len(r.data) {
			return nil, formatErrorf("invalid %s length", r.label)
		}
		if r.data[r.offset] == 0 || (count == 1 && r.data[r.offset] < 0x80) {
			return nil, formatErrorf("noncanonical %s length", r.label)
		}
		for i := 0; i < count; i++ {
			size = size*256 + int(r.data[r.offset])
			r.offset++
		}
	}
	if size < 0 || r.offset > len(r.data)-size {
		return nil, formatErrorf("truncated %s", field)
	}
	value := r.data[r.offset : r.offset+size]
	r.offset += size
	return value, nil
}
func (r *derReader) sequence(field string) (*derReader, error) {
	v, err := r.take(0x30, field)
	if err != nil {
		return nil, err
	}
	return newDER(v, field), nil
}
func (r *derReader) expectOID(expected []byte, field string) error {
	v, err := r.take(0x06, field)
	if err != nil {
		return err
	}
	if !bytes.Equal(v, expected) {
		return formatErrorf("unsupported %s", field)
	}
	return nil
}
func (r *derReader) integer(field string) (int, error) {
	raw, err := r.take(0x02, field)
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 || raw[0]&0x80 != 0 || (len(raw) > 1 && raw[0] == 0 && raw[1] < 0x80) || len(raw) > 8 {
		return 0, formatErrorf("noncanonical %s", field)
	}
	n := 0
	for _, b := range raw {
		if n > (int(^uint(0)>>1)-int(b))/256 {
			return 0, limitErrorf("%s exceeds the numeric limit", field)
		}
		n = n*256 + int(b)
	}
	return n, nil
}
func (r *derReader) finish() error {
	if r.offset != len(r.data) {
		return formatErrorf("trailing bytes in %s", r.label)
	}
	return nil
}

func encodePlainPKCS8(seed, algorithmOID []byte) []byte {
	return derSeq(derInteger(0), derSeq(derOID(algorithmOID)), derOctets(derTLV(0x80, seed)))
}
func parsePlainPKCS8(blob, algorithmOID []byte, expected int) ([]byte, error) {
	root := newDER(blob, "PrivateKeyInfo")
	outer, err := root.sequence("PrivateKeyInfo")
	if err != nil {
		return nil, err
	}
	version, err := outer.integer("version")
	if err != nil || version != 0 {
		return nil, formatErrorf("PKCS#8 version must be zero")
	}
	alg, err := outer.sequence("private key algorithm")
	if err != nil {
		return nil, err
	}
	if err = alg.expectOID(algorithmOID, "private key algorithm OID"); err != nil {
		return nil, err
	}
	if err = alg.finish(); err != nil {
		return nil, err
	}
	wrapped, err := outer.take(0x04, "private key")
	if err != nil {
		return nil, err
	}
	inner := newDER(wrapped, "private key seed")
	seed, err := inner.take(0x80, "private key seed")
	if err != nil {
		return nil, err
	}
	if len(seed) != expected {
		return nil, formatErrorf("private key seed has the wrong length")
	}
	if err = inner.finish(); err != nil {
		return nil, err
	}
	if err = outer.finish(); err != nil {
		return nil, err
	}
	if err = root.finish(); err != nil {
		return nil, err
	}
	return bytes.Clone(seed), nil
}

func encryptPKCS8(plain, passphrase []byte, iterations int) ([]byte, error) {
	if iterations < pkcs8MinIterations || iterations > pkcs8MaxIterations {
		return nil, limitErrorf("iteration count must be between %d and %d", pkcs8MinIterations, pkcs8MaxIterations)
	}
	if len(plain) == 0 || len(plain) > pkcs8MaxDER {
		return nil, limitErrorf("private key information has an invalid size")
	}
	salt := make([]byte, 16)
	iv := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, wrapError(CategoryIO, err, "could not read CSPRNG")
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, wrapError(CategoryIO, err, "could not read CSPRNG")
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, 32)
	if err != nil {
		return nil, wrapError(CategoryPassphrase, err, "key derivation failed")
	}
	defer wipe(key)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	defer wipe(padded)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapError(CategoryProvider, err, "AES-256 unavailable")
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	prf := derSeq(derOID(oidHMACSHA256), derTLV(0x05, nil))
	kdf := derSeq(derOID(oidPBKDF2), derSeq(derOctets(salt), derInteger(iterations), prf))
	enc := derSeq(derOID(oidAES256CBC), derOctets(iv))
	return derSeq(derSeq(derOID(oidPBES2), derSeq(kdf, enc)), derOctets(ciphertext)), nil
}

func decryptPKCS8(blob, passphrase []byte) ([]byte, error) {
	if len(blob) == 0 || len(blob) > pkcs8MaxDER {
		return nil, limitErrorf("encrypted PKCS#8 object has an invalid size")
	}
	root := newDER(blob, "PKCS#8")
	outer, err := root.sequence("EncryptedPrivateKeyInfo")
	if err != nil {
		return nil, err
	}
	alg, err := outer.sequence("encryption algorithm")
	if err != nil {
		return nil, err
	}
	if err = alg.expectOID(oidPBES2, "encryption algorithm OID"); err != nil {
		return nil, err
	}
	params, err := alg.sequence("PBES2 parameters")
	if err != nil {
		return nil, err
	}
	kdf, err := params.sequence("key derivation function")
	if err != nil {
		return nil, err
	}
	if err = kdf.expectOID(oidPBKDF2, "key derivation OID"); err != nil {
		return nil, err
	}
	kp, err := kdf.sequence("PBKDF2 parameters")
	if err != nil {
		return nil, err
	}
	salt, err := kp.take(0x04, "PBKDF2 salt")
	if err != nil || len(salt) != 16 {
		return nil, formatErrorf("PBKDF2 salt must be 16 bytes")
	}
	iterations, err := kp.integer("PBKDF2 iteration count")
	if err != nil {
		return nil, err
	}
	if iterations < pkcs8MinIterations || iterations > pkcs8MaxIterations {
		return nil, limitErrorf("iteration count outside the permitted range")
	}
	prf, err := kp.sequence("PBKDF2 PRF")
	if err != nil {
		return nil, err
	}
	if err = prf.expectOID(oidHMACSHA256, "PBKDF2 PRF OID"); err != nil {
		return nil, err
	}
	null, err := prf.take(0x05, "PBKDF2 PRF NULL parameters")
	if err != nil || len(null) != 0 {
		return nil, formatErrorf("PBKDF2 PRF parameters must be NULL")
	}
	if err = prf.finish(); err != nil {
		return nil, err
	}
	if err = kp.finish(); err != nil {
		return nil, err
	}
	if err = kdf.finish(); err != nil {
		return nil, err
	}
	enc, err := params.sequence("encryption scheme")
	if err != nil {
		return nil, err
	}
	if err = enc.expectOID(oidAES256CBC, "encryption scheme OID"); err != nil {
		return nil, err
	}
	iv, err := enc.take(0x04, "AES-CBC IV")
	if err != nil || len(iv) != 16 {
		return nil, formatErrorf("AES-CBC IV must be 16 bytes")
	}
	if err = enc.finish(); err != nil {
		return nil, err
	}
	if err = params.finish(); err != nil {
		return nil, err
	}
	if err = alg.finish(); err != nil {
		return nil, err
	}
	ciphertext, err := outer.take(0x04, "encrypted private key")
	if err != nil {
		return nil, err
	}
	if err = outer.finish(); err != nil {
		return nil, err
	}
	if err = root.finish(); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext) > pkcs8MaxDER || len(ciphertext)%16 != 0 {
		return nil, formatErrorf("encrypted private key has a noncanonical length")
	}
	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, iterations, 32)
	if err != nil {
		return nil, wrapError(CategoryPassphrase, err, "key derivation failed")
	}
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapError(CategoryProvider, err, "AES-256 unavailable")
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	pad := int(plain[len(plain)-1])
	bad := pad == 0 || pad > 16 || pad > len(plain)
	if !bad {
		for _, b := range plain[len(plain)-pad:] {
			if int(b) != pad {
				bad = true
			}
		}
	}
	if bad {
		wipe(plain)
		return nil, passphraseErrorf("could not decrypt the private key; the passphrase is wrong or the key has been altered")
	}
	result := bytes.Clone(plain[:len(plain)-pad])
	wipe(plain)
	return result, nil
}

func pemPKCS8(der []byte) []byte {
	body := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString(pkcs8Begin)
	for len(body) > 64 {
		b.WriteString(body[:64])
		b.WriteByte('\n')
		body = body[64:]
	}
	b.WriteString(body)
	b.WriteByte('\n')
	b.WriteString(pkcs8End)
	return []byte(b.String())
}
func takePEMPKCS8(blob []byte, offset int) ([]byte, int, error) {
	if offset < 0 || !bytes.HasPrefix(blob[offset:], []byte(pkcs8Begin)) {
		return nil, 0, formatErrorf("identity file is missing an encrypted PKCS#8 object")
	}
	start := offset + len(pkcs8Begin)
	relative := bytes.Index(blob[start:], []byte(pkcs8End))
	if relative < 0 {
		return nil, 0, formatErrorf("unterminated encrypted PKCS#8 object")
	}
	end := start + relative
	encoded := blob[start:end]
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		return nil, 0, formatErrorf("noncanonical encrypted PKCS#8 PEM")
	}
	lines := strings.Split(string(encoded[:len(encoded)-1]), "\n")
	for i, line := range lines {
		if len(line) == 0 || len(line) > 64 || (i < len(lines)-1 && len(line) != 64) {
			return nil, 0, formatErrorf("noncanonical encrypted PKCS#8 PEM wrapping")
		}
	}
	joined := strings.Join(lines, "")
	der, err := base64.StdEncoding.Strict().DecodeString(joined)
	if err != nil {
		return nil, 0, formatErrorf("invalid encrypted PKCS#8 base64")
	}
	next := end + len(pkcs8End)
	if !bytes.Equal(pemPKCS8(der), blob[offset:next]) {
		return nil, 0, formatErrorf("noncanonical encrypted PKCS#8 PEM encoding")
	}
	return der, next, nil
}
func encodeIdentityPEM(kem, sig []byte) []byte {
	return bytes.Join([][]byte{[]byte(identityHeader), pemPKCS8(kem), pemPKCS8(sig)}, nil)
}
func parseIdentityPEM(blob []byte) ([]byte, []byte, error) {
	if !bytes.HasPrefix(blob, []byte(identityHeader)) {
		return nil, nil, formatErrorf("unsupported private identity format")
	}
	kem, n, err := takePEMPKCS8(blob, len(identityHeader))
	if err != nil {
		return nil, nil, err
	}
	sig, n, err := takePEMPKCS8(blob, n)
	if err != nil {
		return nil, nil, err
	}
	if n != len(blob) {
		return nil, nil, formatErrorf("trailing bytes in private identity file")
	}
	return kem, sig, nil
}
