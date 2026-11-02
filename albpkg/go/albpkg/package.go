package albpkg

import (
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ProgressHook is called as (bytesDone, chunksDone). Returning an error
// cancels the operation; nothing is published.
type ProgressHook func(bytesDone int64, chunksDone int64) error

// ---- Header --------------------------------------------------------------

// Header is the package header (FORMAT.md 3.1).
type Header struct {
	SenderFpr    []byte
	RecipientFpr []byte
	PackageID    []byte
	KemCt        []byte
	ChunkSize    uint32
	Flags        uint32
}

// Serialize renders the canonical header.
func (h *Header) Serialize() ([]byte, error) {
	if len(h.SenderFpr) != FprLen {
		return nil, formatErrorf("sender fingerprint must be 32 bytes")
	}
	if len(h.RecipientFpr) != FprLen {
		return nil, formatErrorf("recipient fingerprint must be 32 bytes")
	}
	if len(h.PackageID) != PackageIDLen {
		return nil, formatErrorf("package identifier must be 16 bytes")
	}
	if len(h.KemCt) != KemCtLen {
		return nil, formatErrorf("ML-KEM-768 encapsulation has the wrong length")
	}
	if h.ChunkSize != ChunkSize {
		return nil, unsupportedErrorf("only a 1 MiB chunk size is defined for ALBPKG-1")
	}
	if h.Flags != 0 {
		return nil, unsupportedErrorf("no header flags are defined for ALBPKG-1")
	}

	out := make([]byte, 0, HeaderLen)
	out = append(out, PackageMagic...)
	out = append(out, encU16(FormatVersion)...)
	out = append(out, encU16(SuiteID)...)
	out = append(out, encU32(HeaderLen)...)
	out = append(out, encU32(int(h.Flags))...)
	out = append(out, encU32(int(h.ChunkSize))...)
	out = append(out, h.SenderFpr...)
	out = append(out, h.RecipientFpr...)
	out = append(out, h.PackageID...)
	out = append(out, encU16(KemCtLen)...)
	out = append(out, h.KemCt...)

	if len(out) != HeaderLen {
		return nil, formatErrorf("internal: header serialization length mismatch")
	}
	return out, nil
}

// Digest returns SHA-256 over the serialized header.
func (h *Header) Digest() ([]byte, error) {
	blob, err := h.Serialize()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	return sum[:], nil
}

// ParseHeader strictly decodes a package header.
func ParseHeader(blob []byte) (*Header, error) {
	if len(blob) != HeaderLen {
		return nil, formatErrorf("header must be exactly %d bytes, got %d",
			HeaderLen, len(blob))
	}
	r := newByteReader(blob, "package header")
	if err := r.expect(PackageMagic, "package magic"); err != nil {
		return nil, err
	}
	version, err := r.u16("format version")
	if err != nil {
		return nil, err
	}
	if version != FormatVersion {
		return nil, unsupportedErrorf("unsupported format version %d", version)
	}
	suiteID, err := r.u16("suite id")
	if err != nil {
		return nil, err
	}
	if suiteID != SuiteID {
		return nil, unsupportedErrorf("unsupported suite id 0x%04x", suiteID)
	}
	headerLen, err := r.u32("header length")
	if err != nil {
		return nil, err
	}
	if headerLen != HeaderLen {
		return nil, formatErrorf("noncanonical header length")
	}
	flags, err := r.u32("flags")
	if err != nil {
		return nil, err
	}
	if flags != 0 {
		return nil, unsupportedErrorf("unknown header flag bits set: 0x%08x", flags)
	}
	chunkSize, err := r.u32("chunk size")
	if err != nil {
		return nil, err
	}
	if chunkSize != ChunkSize {
		return nil, unsupportedErrorf("unsupported chunk size %d", chunkSize)
	}
	senderFpr, err := r.take(FprLen, "sender fingerprint")
	if err != nil {
		return nil, err
	}
	recipientFpr, err := r.take(FprLen, "recipient fingerprint")
	if err != nil {
		return nil, err
	}
	packageID, err := r.take(PackageIDLen, "package identifier")
	if err != nil {
		return nil, err
	}
	kemCtLen, err := r.u16("encapsulation length")
	if err != nil {
		return nil, err
	}
	if kemCtLen != KemCtLen {
		return nil, formatErrorf("noncanonical encapsulation length")
	}
	kemCt, err := r.take(kemCtLen, "encapsulation")
	if err != nil {
		return nil, err
	}
	if err := r.finish(); err != nil {
		return nil, err
	}

	return &Header{
		SenderFpr:    bytes.Clone(senderFpr),
		RecipientFpr: bytes.Clone(recipientFpr),
		PackageID:    bytes.Clone(packageID),
		KemCt:        bytes.Clone(kemCt),
		ChunkSize:    chunkSize,
		Flags:        flags,
	}, nil
}

// ---- Key derivation ------------------------------------------------------

func hkdfKey(ikm, salt, info []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, ikm, salt, string(info), AeadKeyLen)
	if err != nil {
		return nil, wrapError(CategoryProvider, err, "HKDF-SHA-256 failed")
	}
	return key, nil
}

// DeriveMaster derives the per-package master key.
func DeriveMaster(sharedSecret, headerDigest []byte) ([]byte, error) {
	if len(sharedSecret) != KemSSLen {
		return nil, formatErrorf("shared secret has the wrong length")
	}
	if len(headerDigest) != 32 {
		return nil, formatErrorf("header digest has the wrong length")
	}
	return hkdfKey(sharedSecret, headerDigest, InfoMaster)
}

// DeriveChunkKey derives the single-use key for one chunk.
func DeriveChunkKey(master, headerDigest []byte, index int64) ([]byte, error) {
	if index < 0 || index >= MaxChunks {
		return nil, limitErrorf("chunk index %d out of range", index)
	}
	info := append(bytes.Clone(InfoChunk), encU64(uint64(index))...)
	return hkdfKey(master, headerDigest, info)
}

// DeriveCompletionKey derives the single-use key for the completion record.
func DeriveCompletionKey(master, headerDigest []byte) ([]byte, error) {
	return hkdfKey(master, headerDigest, InfoComplete)
}

func chunkAad(headerDigest []byte, index int64, ptLen int, final bool) []byte {
	out := make([]byte, 0, len(AadChunkPrefix)+32+8+4+1)
	out = append(out, AadChunkPrefix...)
	out = append(out, headerDigest...)
	out = append(out, encU64(uint64(index))...)
	out = append(out, encU32(ptLen)...)
	finalByte := 0
	if final {
		finalByte = 1
	}
	out = append(out, encU8(finalByte)...)
	return out
}

func completionAad(headerDigest []byte, totalBytes, chunkCount int64) []byte {
	out := make([]byte, 0, len(AadCompletePfx)+32+16)
	out = append(out, AadCompletePfx...)
	out = append(out, headerDigest...)
	out = append(out, encU64(uint64(totalBytes))...)
	out = append(out, encU64(uint64(chunkCount))...)
	return out
}

// SignatureMessage builds the domain-separated message that is signed.
func SignatureMessage(bodySha512 []byte) ([]byte, error) {
	if len(bodySha512) != 64 {
		return nil, formatErrorf("body digest must be SHA-512")
	}
	return append(bytes.Clone(SigContextPrefix), bodySha512...), nil
}

// ---- Results -------------------------------------------------------------

// SealResult describes a package that was written.
type SealResult struct {
	PackagePath          string
	PackageID            []byte
	TotalBytes           int64
	ChunkCount           int64
	RecipientFingerprint string
}

// OpenResult describes a package that was opened.
type OpenResult struct {
	OutputPath        string
	PackageID         []byte
	TotalBytes        int64
	ChunkCount        int64
	SenderName        string
	SenderFingerprint string
}

// hashingWriter writes through to a file while hashing every byte.
type hashingWriter struct {
	file    *os.File
	hash    interface{ Write([]byte) (int, error) }
	written int64
}

func (w *hashingWriter) write(data []byte) error {
	if err := writeAll(w.file, data); err != nil {
		return err
	}
	if _, err := w.hash.Write(data); err != nil {
		return wrapError(CategoryIO, err, "hashing failed")
	}
	w.written += int64(len(data))
	return nil
}

// ---- Sealing -------------------------------------------------------------

// SealOptions configures SealFile.
type SealOptions struct {
	Sender     *Identity
	Recipient  *Contact
	Public     *PublicIdentity // used only when Recipient is nil (tests)
	InputPath  string
	OutputPath string
	Overwrite  bool
	Progress   ProgressHook
}

// SealFile encrypts and signs a file into an ALBPKG/1 package.
//
// The recipient must be a verified contact. A bare PublicIdentity is accepted
// only for tests; the CLI always passes a Contact.
func SealFile(options SealOptions) (*SealResult, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}

	if options.Recipient == nil {
		return nil, trustErrorf("a verified Contact is required")
	}
	recipientPublic := options.Public
	if options.Recipient != nil {
		if err := options.Recipient.RequireUsable(); err != nil {
			return nil, err
		}
		recipientPublic = options.Recipient.Public
	}
	if recipientPublic == nil {
		return nil, trustErrorf("no recipient was supplied")
	}

	info, err := os.Stat(options.InputPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ioErrorf("input is not a regular file: %s", options.InputPath)
	}
	if info.Size() > MaxPlaintext {
		return nil, limitErrorf("input is %d bytes; the maximum is %d bytes (1 TiB)",
			info.Size(), int64(MaxPlaintext))
	}

	kemKey, err := recipientPublic.KemKey()
	if err != nil {
		return nil, err
	}
	sharedSecret, kemCt := kemKey.Encapsulate()
	defer wipe(sharedSecret)

	packageID := make([]byte, PackageIDLen)
	if _, err := rand.Read(packageID); err != nil {
		return nil, wrapError(CategoryIO, err, "could not read from the system CSPRNG")
	}

	header := &Header{
		SenderFpr:    options.Sender.Fingerprint(),
		RecipientFpr: recipientPublic.Fingerprint(),
		PackageID:    packageID,
		KemCt:        kemCt,
		ChunkSize:    ChunkSize,
	}
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, err
	}
	headerDigestArr := sha256.Sum256(headerBytes)
	headerDigest := headerDigestArr[:]

	master, err := DeriveMaster(sharedSecret, headerDigest)
	if err != nil {
		return nil, err
	}
	defer wipe(master)

	source, err := os.Open(options.InputPath)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot open the input file")
	}
	defer source.Close()

	var (
		totalBytes int64
		chunkCount int64
	)

	err = withAtomicOutput(options.OutputPath, options.Overwrite, func(dest *os.File) error {
		out := &hashingWriter{file: dest, hash: sha512.New()}
		if err := out.write(headerBytes); err != nil {
			return err
		}

		// One-chunk look-ahead so the final marker is known before the chunk it
		// belongs to is emitted, without seeking the input.
		var readOffset int64
		pending, err := readAtMostAt(source, ChunkSize, readOffset)
		if err != nil {
			return err
		}
		readOffset += int64(len(pending))

		for {
			lookahead, err := readAtMostAt(source, ChunkSize, readOffset)
			if err != nil {
				return err
			}
			readOffset += int64(len(lookahead))
			final := len(lookahead) == 0
			if len(pending) != ChunkSize && !final {
				return ioErrorf("short read from input before end of file")
			}

			if err := emitChunk(out, master, headerDigest, chunkCount, pending, final); err != nil {
				return err
			}
			totalBytes += int64(len(pending))
			if totalBytes > MaxPlaintext {
				return limitErrorf("plaintext exceeds the 1 TiB maximum")
			}
			chunkCount++
			if chunkCount > MaxChunks {
				return limitErrorf("package exceeds the maximum chunk count")
			}
			if options.Progress != nil {
				if err := options.Progress(totalBytes, chunkCount); err != nil {
					return err
				}
			}
			if final {
				break
			}
			pending = lookahead
		}

		// Completion record.
		doneKey, err := DeriveCompletionKey(master, headerDigest)
		if err != nil {
			return err
		}
		defer wipe(doneKey)
		aead, err := newGCM(doneKey)
		if err != nil {
			return err
		}
		completionPt := append(encU64(uint64(totalBytes)), encU64(uint64(chunkCount))...)
		completionCt := aead.Seal(nil, AeadNonce,
			completionPt, completionAad(headerDigest, totalBytes, chunkCount))
		if err := out.write(completionCt); err != nil {
			return err
		}

		// Signature over every byte emitted so far.
		digest, ok := out.hash.(interface{ Sum([]byte) []byte })
		if !ok {
			return formatErrorf("internal: body hash is not summable")
		}
		message, err := SignatureMessage(digest.Sum(nil))
		if err != nil {
			return err
		}
		signature := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(options.Sender.SigPrivate, message, nil, false, signature); err != nil {
			return wrapError(CategoryProvider, err, "ML-DSA-65 signing failed")
		}
		if len(signature) != SigLen {
			return formatErrorf("unexpected ML-DSA-65 signature length")
		}
		if err := writeAll(dest, signature); err != nil {
			return err
		}
		if err := writeAll(dest, encU32(len(signature))); err != nil {
			return err
		}
		return writeAll(dest, SigTrailerMagic)
	})
	if err != nil {
		return nil, err
	}

	return &SealResult{
		PackagePath:          options.OutputPath,
		PackageID:            packageID,
		TotalBytes:           totalBytes,
		ChunkCount:           chunkCount,
		RecipientFingerprint: recipientPublic.FingerprintText(),
	}, nil
}

func emitChunk(out *hashingWriter, master, headerDigest []byte,
	index int64, plaintext []byte, final bool) error {

	key, err := DeriveChunkKey(master, headerDigest, index)
	if err != nil {
		return err
	}
	defer wipe(key)
	aead, err := newGCM(key)
	if err != nil {
		return err
	}
	ct := aead.Seal(nil, AeadNonce, plaintext,
		chunkAad(headerDigest, index, len(plaintext), final))

	finalByte := 0
	if final {
		finalByte = 1
	}
	if err := out.write(encU8(finalByte)); err != nil {
		return err
	}
	if err := out.write(encU32(len(plaintext))); err != nil {
		return err
	}
	return out.write(ct)
}

// ---- Opening -------------------------------------------------------------

// OpenOptions configures OpenFile.
type OpenOptions struct {
	Recipient  *Identity
	Contacts   *ContactStore
	InputPath  string
	OutputPath string
	Overwrite  bool
	Progress   ProgressHook
}

// OpenFile verifies and decrypts an ALBPKG/1 package.
//
// The signature is verified against the trusted sender before any plaintext is
// produced, and the result is published only after the completion record has
// verified.
func OpenFile(options OpenOptions) (*OpenResult, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}

	info, err := os.Stat(options.InputPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ioErrorf("package is not a regular file: %s", options.InputPath)
	}

	file, err := os.Open(options.InputPath)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot open the package")
	}
	defer file.Close()

	var result *OpenResult
	err = withPrivateSpool(filepath.Dir(options.OutputPath), func(spool *os.File, name string) error {
		block := make([]byte, ChunkSize)
		var size int64
		for {
			n, readErr := file.Read(block)
			if n > 0 {
				size += int64(n)
				if size > MaxPackageSize {
					return limitErrorf("package exceeds limit")
				}
				if e := writeAll(spool, block[:n]); e != nil {
					return e
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
			if n == 0 {
				return io.ErrNoProgress
			}
		}
		if e := spool.Sync(); e != nil {
			return e
		}
		snapshot, e := os.Open(name)
		if e != nil {
			return e
		}
		defer snapshot.Close()
		result, e = openFromFile(snapshot, size, options)
		return e
	})
	return result, err
}

// OpenBytes opens a package held in memory by spooling it, bounded, to a
// private temporary file first: the signature at the tail must be verified
// before any decryption begins.
func OpenBytes(data []byte, options OpenOptions) (*OpenResult, error) {
	if err := CheckProvider(); err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxPackageSize {
		return nil, limitErrorf("package is larger than the format permits (%d bytes)",
			len(data))
	}

	var result *OpenResult
	err := withPrivateSpool(filepath.Dir(options.OutputPath), func(file *os.File, temp string) error {
		if err := writeAll(file, data); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return wrapError(CategoryIO, err, "could not flush the spool file")
		}
		reread, err := os.Open(temp)
		if err != nil {
			return wrapError(CategoryIO, err, "could not reopen the spool file")
		}
		defer reread.Close()
		result, err = openFromFile(reread, int64(len(data)), options)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func openFromFile(file *os.File, size int64, options OpenOptions) (*OpenResult, error) {
	if size < MinPackageSize {
		return nil, formatErrorf("package is too small to be valid (%d bytes)", size)
	}
	if size > MaxPackageSize {
		return nil, limitErrorf("package is larger than the format permits (%d bytes)", size)
	}

	// -- 1. header --
	headerBytes, err := readExactAt(file, HeaderLen, 0, "package header")
	if err != nil {
		return nil, err
	}
	header, err := ParseHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	headerDigestArr := sha256.Sum256(headerBytes)
	headerDigest := headerDigestArr[:]

	// -- 2. trust --
	if !FingerprintsEqual(header.RecipientFpr, options.Recipient.Fingerprint()) {
		text, _ := FormatFingerprint(header.RecipientFpr)
		return nil, trustErrorf("this package is addressed to a different recipient (%s)", text)
	}
	sender, err := options.Contacts.Require(header.SenderFpr)
	if err != nil {
		return nil, err
	}
	if err := sender.RequireUsable(); err != nil {
		return nil, err
	}

	// -- 3. signature, before any decryption --
	trailer, err := readExactAt(file, SigTrailerLen, size-SigTrailerLen, "signature trailer")
	if err != nil {
		return nil, err
	}
	sigLen := binary.BigEndian.Uint32(trailer[:4])
	if !bytes.Equal(trailer[4:], SigTrailerMagic) {
		return nil, formatErrorf("missing signature trailer; the package is truncated or padded")
	}
	if sigLen != SigLen {
		return nil, formatErrorf("noncanonical signature length %d", sigLen)
	}

	bodyLen := size - SigTrailerLen - int64(sigLen)
	if bodyLen < HeaderLen {
		return nil, formatErrorf("signature block overlaps the package body")
	}

	signature, err := readExactAt(file, int(sigLen), bodyLen, "signature")
	if err != nil {
		return nil, err
	}

	bodyHash := sha512.New()
	remaining := bodyLen
	var cursor int64
	for remaining > 0 {
		want := int64(1 << 20)
		if remaining < want {
			want = remaining
		}
		block, err := readAtMostAt(file, int(want), cursor)
		if err != nil {
			return nil, err
		}
		if len(block) == 0 {
			return nil, formatErrorf("package body is shorter than its framing declares")
		}
		bodyHash.Write(block)
		remaining -= int64(len(block))
		cursor += int64(len(block))
	}

	message, err := SignatureMessage(bodyHash.Sum(nil))
	if err != nil {
		return nil, err
	}
	sigKey, err := sender.Public.SigKey()
	if err != nil {
		return nil, err
	}
	if !mldsa65.Verify(sigKey, message, nil, signature) {
		return nil, authErrorf("signature does not verify against contact '%s'", sender.Name)
	}

	// -- 4. decrypt --
	sharedSecret, err := options.Recipient.KemPrivate.Decapsulate(header.KemCt)
	if err != nil {
		return nil, authErrorf("ML-KEM decapsulation failed for this encapsulation")
	}
	defer wipe(sharedSecret)

	master, err := DeriveMaster(sharedSecret, headerDigest)
	if err != nil {
		return nil, err
	}
	defer wipe(master)

	var (
		totalBytes int64
		chunkCount int64
	)

	err = withAtomicOutput(options.OutputPath, options.Overwrite, func(dest *os.File) error {
		offset := int64(HeaderLen)
		bodyEnd := bodyLen - CompletionLen
		if bodyEnd < offset {
			return formatErrorf("package has no room for a completion record")
		}
		sawFinal := false

		for offset < bodyEnd {
			if chunkCount >= MaxChunks {
				return limitErrorf("package exceeds the maximum chunk count")
			}
			if sawFinal {
				return formatErrorf("chunk records continue past the final chunk")
			}

			frame, err := readExactAt(file, 5, offset, "chunk framing")
			if err != nil {
				return err
			}
			finalFlag := frame[0]
			if finalFlag != 0 && finalFlag != 1 {
				return formatErrorf("noncanonical final marker %d", finalFlag)
			}
			ptLen := binary.BigEndian.Uint32(frame[1:5])
			if ptLen > header.ChunkSize {
				return limitErrorf("chunk %d declares %d bytes, over the %d-byte chunk size",
					chunkCount, ptLen, header.ChunkSize)
			}
			final := finalFlag == 1
			if !final && ptLen != header.ChunkSize {
				return formatErrorf("chunk %d is short but is not marked final", chunkCount)
			}
			if ptLen == 0 && !(final && chunkCount == 0) {
				return formatErrorf("only a lone final chunk may be empty")
			}

			ctLen, err := checkedAdd(int(ptLen), AeadTagLen, MaxPackageSize, "chunk record")
			if err != nil {
				return err
			}
			next := offset + 5 + int64(ctLen)
			if next > bodyEnd {
				return formatErrorf("chunk %d runs past the completion record", chunkCount)
			}

			ct, err := readExactAt(file, ctLen, offset+5, "chunk")
			if err != nil {
				return err
			}
			key, err := DeriveChunkKey(master, headerDigest, chunkCount)
			if err != nil {
				return err
			}
			aead, err := newGCM(key)
			if err != nil {
				wipe(key)
				return err
			}
			plaintext, err := aead.Open(nil, AeadNonce, ct,
				chunkAad(headerDigest, chunkCount, int(ptLen), final))
			wipe(key)
			if err != nil {
				return authErrorf("authentication failed on chunk %d", chunkCount)
			}
			if len(plaintext) != int(ptLen) {
				return formatErrorf("chunk %d plaintext length mismatch", chunkCount)
			}
			if err := writeAll(dest, plaintext); err != nil {
				return err
			}
			wipe(plaintext)

			totalBytes += int64(ptLen)
			if totalBytes > MaxPlaintext {
				return limitErrorf("plaintext exceeds the 1 TiB maximum")
			}
			chunkCount++
			sawFinal = final
			offset = next
			if options.Progress != nil {
				if err := options.Progress(totalBytes, chunkCount); err != nil {
					return err
				}
			}
		}

		if !sawFinal {
			return formatErrorf("package has no final chunk; it is truncated")
		}
		if offset != bodyEnd {
			return formatErrorf("chunk records do not end at the completion record")
		}

		// -- 5. completion --
		completionCt, err := readExactAt(file, CompletionLen, bodyEnd, "completion record")
		if err != nil {
			return err
		}
		doneKey, err := DeriveCompletionKey(master, headerDigest)
		if err != nil {
			return err
		}
		defer wipe(doneKey)
		aead, err := newGCM(doneKey)
		if err != nil {
			return err
		}
		completionPt, err := aead.Open(nil, AeadNonce, completionCt,
			completionAad(headerDigest, totalBytes, chunkCount))
		if err != nil {
			return authErrorf(
				"completion record does not match the decrypted contents; " +
					"the package is truncated or altered")
		}
		expected := append(encU64(uint64(totalBytes)), encU64(uint64(chunkCount))...)
		if !bytes.Equal(completionPt, expected) {
			return authErrorf("completion record contents disagree with the package")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &OpenResult{
		OutputPath:        options.OutputPath,
		PackageID:         header.PackageID,
		TotalBytes:        totalBytes,
		ChunkCount:        chunkCount,
		SenderName:        sender.Name,
		SenderFingerprint: sender.FingerprintText(),
	}, nil
}
