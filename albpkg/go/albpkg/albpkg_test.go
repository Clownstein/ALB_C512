// Acceptance tests for the ALBPKG/1 Go port.
//
// Mirrors the Python and TypeScript suites: round-trips including empty files
// and chunk boundaries, and explicit rejection of wrong recipients, untrusted
// or revoked senders, altered headers, substituted encapsulations, bad
// signatures and tags, reordered or duplicated chunks, truncation, appended
// data, and overflow.
//
// Run:  go test ./...
package albpkg

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const passphrase = "correct horse battery staple"

func provider(string) (string, error) { return passphrase, nil }

// Generating post-quantum keypairs is not free; share three identities across
// the whole suite rather than per test.
var alice, bob, mallory *Identity

func TestMain(m *testing.M) {
	var err error
	if alice, err = GenerateIdentity(); err != nil {
		panic(err)
	}
	if bob, err = GenerateIdentity(); err != nil {
		panic(err)
	}
	if mallory, err = GenerateIdentity(); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func mustStore(t *testing.T, dir string) *ContactStore {
	t.Helper()
	store, err := NewContactStore(filepath.Join(dir, "contacts"))
	if err != nil {
		t.Fatalf("NewContactStore: %v", err)
	}
	return store
}

// trustingStore returns a store that has imported and verified `who`.
func trustingStore(t *testing.T, dir string, who *Identity, name string) *ContactStore {
	t.Helper()
	store := mustStore(t, dir)
	if _, err := store.ImportContact(name, who.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	if _, err := store.VerifyContact(name,
		hex.EncodeToString(who.Public().Fingerprint())); err != nil {
		t.Fatalf("VerifyContact: %v", err)
	}
	return store
}

func seal(t *testing.T, dir string, sender *Identity, recipient *PublicIdentity,
	data []byte, name string) string {
	t.Helper()
	source := filepath.Join(dir, name+".in")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	out := filepath.Join(dir, name)
	if _, err := SealFile(SealOptions{
		Sender:     sender,
		Recipient:  &Contact{Name: "fixture", Public: recipient, Trust: TrustVerified},
		InputPath:  source,
		OutputPath: out,
		Overwrite:  true,
	}); err != nil {
		t.Fatalf("SealFile: %v", err)
	}
	return out
}

func openPkg(pkg string, recipient *Identity, store *ContactStore, out string) (*OpenResult, error) {
	return OpenFile(OpenOptions{
		Recipient:  recipient,
		Contacts:   store,
		InputPath:  pkg,
		OutputPath: out,
		Overwrite:  true,
	})
}

// resign re-signs a tampered body so a test isolates a non-signature defence.
func resign(t *testing.T, blob []byte, sender *Identity) []byte {
	t.Helper()
	body := blob
	if len(blob) > SigTrailerLen && bytes.Equal(blob[len(blob)-8:], SigTrailerMagic) {
		body = blob[:len(blob)-SigTrailerLen-SigLen]
	}
	digest := sha512.Sum512(body)
	message, err := SignatureMessage(digest[:])
	if err != nil {
		t.Fatalf("SignatureMessage: %v", err)
	}
	signature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(sender.SigPrivate, message, nil, false, signature); err != nil {
		t.Fatalf("SignTo: %v", err)
	}
	out := append(bytes.Clone(body), signature...)
	out = append(out, encU32(len(signature))...)
	return append(out, SigTrailerMagic...)
}

func flip(blob []byte, offset int) []byte {
	out := bytes.Clone(blob)
	out[offset] ^= 0x01
	return out
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	return data
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", filepath.Base(path), err)
	}
}

func requireCategory(t *testing.T, err error, want Category) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a %s error, got nil", want)
	}
	var structured *Error
	if !errors.As(err, &structured) {
		t.Fatalf("expected a structured error, got %T: %v", err, err)
	}
	if structured.Cat != want {
		t.Fatalf("expected category %s, got %s (%v)", want, structured.Cat, err)
	}
}

// ---- Identity and fingerprints ------------------------------------------

func TestIdentityKeysAreIndependent(t *testing.T) {
	public := alice.Public()
	if bytes.Equal(public.KemPublicBytes, public.SigPublicBytes) {
		t.Fatal("the encryption key and the signing key must be independent")
	}
	if len(public.PubID()) != PubIDLen || PubIDLen != 3150 {
		t.Fatalf("canonical public identity must be 3150 bytes, got %d", len(public.PubID()))
	}
}

func TestFingerprintCoversBothKeys(t *testing.T) {
	swapped := &PublicIdentity{
		KemPublicBytes: alice.Public().KemPublicBytes,
		SigPublicBytes: bob.Public().SigPublicBytes,
	}
	if FingerprintsEqual(swapped.Fingerprint(), alice.Fingerprint()) ||
		FingerprintsEqual(swapped.Fingerprint(), bob.Fingerprint()) {
		t.Fatal("a swapped key pair must not reproduce either fingerprint")
	}
}

func TestFingerprintFormattingRoundTrip(t *testing.T) {
	text := alice.Public().FingerprintText()
	if len(text) != 64+7 {
		t.Fatalf("grouped fingerprint should be 71 characters, got %d", len(text))
	}
	parsed, err := ParseFingerprint(text)
	if err != nil || !FingerprintsEqual(parsed, alice.Fingerprint()) {
		t.Fatalf("grouped fingerprint did not round trip: %v", err)
	}
	parsed, err = ParseFingerprint(hex.EncodeToString(alice.Fingerprint()))
	if err != nil || !FingerprintsEqual(parsed, alice.Fingerprint()) {
		t.Fatalf("plain fingerprint did not round trip: %v", err)
	}
}

func TestTruncatedFingerprintsRejected(t *testing.T) {
	for _, bad := range []string{"", "abcd", "1a2b3c4d", strings.Repeat("z", 64),
		strings.Repeat("ab", 33)} {
		if _, err := ParseFingerprint(bad); err == nil {
			t.Fatalf("ParseFingerprint(%q) should have failed", bad)
		}
	}
}

func TestArmoredRoundTrip(t *testing.T) {
	restored, err := PublicIdentityFromArmored(alice.Public().ToArmored())
	if err != nil {
		t.Fatalf("PublicIdentityFromArmored: %v", err)
	}
	if !FingerprintsEqual(restored.Fingerprint(), alice.Fingerprint()) {
		t.Fatal("armored round trip changed the fingerprint")
	}
}

func TestArmoredFingerprintHeaderMustMatch(t *testing.T) {
	armored := strings.Replace(alice.Public().ToArmored(),
		hex.EncodeToString(alice.Fingerprint()),
		hex.EncodeToString(bob.Fingerprint()), 1)
	if _, err := PublicIdentityFromArmored(armored); err == nil {
		t.Fatal("a mismatched fingerprint header must be rejected")
	}
}

func TestNoncanonicalPubIDRejected(t *testing.T) {
	base := alice.Public().PubID()
	mutations := map[string][]byte{
		"truncated":      base[:len(base)-1],
		"extended":       append(bytes.Clone(base), 0),
		"bad magic":      append([]byte("XXXXXXXX"), base[8:]...),
		"wrong suite":    append(append(bytes.Clone(base[:8]), 0, 2), base[10:]...),
		"wrong kem size": append(append(bytes.Clone(base[:10]), 0, 16), base[12:]...),
	}
	for name, mutated := range mutations {
		if _, err := PublicIdentityFromPubID(mutated); err == nil {
			t.Fatalf("%s public identity must be rejected", name)
		}
	}
}

// ---- Private identity storage -------------------------------------------

func TestIdentityFileRoundTripAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	if err := SaveIdentity(alice, path, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if !permissionsAreOwnerOnly(path) {
		t.Fatal("identity file must be owner-only")
	}
	loaded, err := LoadIdentity(path, provider)
	if err != nil {
		t.Fatalf("LoadIdentity: %v", err)
	}
	defer loaded.Close()
	if !FingerprintsEqual(loaded.Fingerprint(), alice.Fingerprint()) {
		t.Fatal("loaded identity has a different fingerprint")
	}
}

func TestIdentityFileWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	if err := SaveIdentity(alice, path, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	_, err := LoadIdentity(path, func(string) (string, error) {
		return "wrong passphrase", nil
	})
	requireCategory(t, err, CategoryPassphrase)
}

func TestShortPassphraseRejected(t *testing.T) {
	dir := t.TempDir()
	err := SaveIdentity(alice, filepath.Join(dir, "id.key"),
		func(string) (string, error) { return "short", nil }, false, 0)
	requireCategory(t, err, CategoryPassphrase)
}

func TestIdentityFileTamperingRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	if err := SaveIdentity(alice, path, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	blob := mustRead(t, path)

	// Flipping a byte in the sealed seeds must fail authentication, not
	// silently yield a different key.
	mustWrite(t, path, flip(blob, len(blob)-5))
	if _, err := LoadIdentity(path, provider); err == nil {
		t.Fatal("a tampered identity file must be rejected")
	}

	// Truncation and trailing bytes are framing errors.
	mustWrite(t, path, blob[:len(blob)-5])
	if _, err := LoadIdentity(path, provider); err == nil {
		t.Fatal("a truncated identity file must be rejected")
	}
	mustWrite(t, path, append(bytes.Clone(blob), 0))
	if _, err := LoadIdentity(path, provider); err == nil {
		t.Fatal("trailing bytes in an identity file must be rejected")
	}
}

func TestIdentityFileIterationBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	err := SaveIdentity(alice, path, provider, false, 100)
	requireCategory(t, err, CategoryLimit)

	if err := SaveIdentity(alice, path, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	blob := mustRead(t, path)
	// Rewrite the canonical DER integer 600000 to canonical 65536, below the floor.
	kem, sig, parseErr := parseIdentityPEM(blob)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	kem = bytes.Replace(kem, []byte{0x02, 0x03, 0x09, 0x27, 0xc0}, []byte{0x02, 0x03, 0x01, 0x00, 0x00}, 1)
	mustWrite(t, path, encodeIdentityPEM(kem, sig))
	_, err = LoadIdentity(path, provider)
	requireCategory(t, err, CategoryLimit)
}

func TestIdentityFileSaltIsFreshEveryWrite(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.key")
	second := filepath.Join(dir, "b.key")
	if err := SaveIdentity(alice, first, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := SaveIdentity(alice, second, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// Same identity and passphrase must still produce fresh encryption parameters.
	if bytes.Equal(mustRead(t, first), mustRead(t, second)) {
		t.Fatal("encrypted PKCS#8 parameters must be fresh on every write")
	}
}

func TestSaveIdentityDoesNotClobber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id.key")
	if err := SaveIdentity(alice, path, provider, false, 0); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	original := mustRead(t, path)
	if err := SaveIdentity(bob, path, provider, false, 0); err == nil {
		t.Fatal("overwriting an identity file must require the overwrite flag")
	}
	if !bytes.Equal(mustRead(t, path), original) {
		t.Fatal("the existing identity file must be left untouched")
	}
}

// ---- Contact trust -------------------------------------------------------

func TestImportIsUnverifiedAndUnusable(t *testing.T) {
	store := mustStore(t, t.TempDir())
	contact, err := store.ImportContact("alice", alice.Public())
	if err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	if contact.Trust != TrustUnverified {
		t.Fatalf("a fresh import must be unverified, got %s", contact.Trust)
	}
	requireCategory(t, contact.RequireUsable(), CategoryTrust)
}

func TestVerifyRequiresExactFingerprint(t *testing.T) {
	store := mustStore(t, t.TempDir())
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	_, err := store.VerifyContact("alice", hex.EncodeToString(bob.Fingerprint()))
	requireCategory(t, err, CategoryTrust)

	contact, err := store.ByName("alice")
	if err != nil || contact.Trust != TrustUnverified {
		t.Fatal("a failed verification must leave the contact unverified")
	}
	if _, err := store.VerifyContact("alice", alice.Public().FingerprintText()); err != nil {
		t.Fatalf("VerifyContact: %v", err)
	}
	contact, _ = store.ByName("alice")
	if contact.Trust != TrustVerified {
		t.Fatal("a matching fingerprint must verify the contact")
	}
}

func TestKeyReplacementResetsTrust(t *testing.T) {
	store := mustStore(t, t.TempDir())
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	if _, err := store.VerifyContact("alice", hex.EncodeToString(alice.Fingerprint())); err != nil {
		t.Fatalf("VerifyContact: %v", err)
	}
	if _, err := store.ImportContact("alice", bob.Public()); err != nil {
		t.Fatalf("ImportContact (replacement): %v", err)
	}
	contacts, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, contact := range contacts {
		if contact.Trust != TrustUnverified {
			t.Fatalf("key replacement must reset trust, found %s", contact.Trust)
		}
	}
	if _, err := store.ByName("alice"); err == nil {
		t.Fatal("an ambiguous name must not resolve")
	}
}

func TestFailedReplacementDemotesOldFingerprintFirst(t *testing.T) {
	store := mustStore(t, t.TempDir())
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyContact("alice", hex.EncodeToString(alice.Fingerprint())); err != nil {
		t.Fatal(err)
	}
	// Inject failure at the new-record write after the old record is durable.
	if _, err := store.importContactWithWriter("alice", bob.Public(), func(contact *Contact) error {
		if FingerprintsEqual(contact.Fingerprint(), bob.Fingerprint()) {
			return errors.New("injected publication failure")
		}
		return store.write(contact)
	}); err == nil {
		t.Fatal("replacement must fail when the new record cannot be published")
	}
	old, err := store.Require(alice.Fingerprint())
	if err != nil || old.Trust != TrustUnverified {
		t.Fatalf("old fingerprint remained trusted after failed replacement: %v, %v", old, err)
	}
}

func TestRevokedContactRejected(t *testing.T) {
	store := mustStore(t, t.TempDir())
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	if _, err := store.VerifyContact("alice", hex.EncodeToString(alice.Fingerprint())); err != nil {
		t.Fatalf("VerifyContact: %v", err)
	}
	contact, err := store.Revoke("alice")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	requireCategory(t, contact.RequireUsable(), CategoryTrust)
}

func TestContactFileTamperingRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	entries, _ := os.ReadDir(store.Directory)
	path := filepath.Join(store.Directory, entries[0].Name())
	mustWrite(t, path, []byte(strings.Replace(string(mustRead(t, path)),
		`"unverified"`, `"nonsense"`, 1)))
	if _, err := store.List(); err == nil {
		t.Fatal("an unknown trust state must be rejected")
	}
}

func TestContactFileRenamedRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	entries, _ := os.ReadDir(store.Directory)
	if err := os.Rename(filepath.Join(store.Directory, entries[0].Name()),
		filepath.Join(store.Directory, hex.EncodeToString(bob.Fingerprint())+".contact")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := store.List(); err == nil {
		t.Fatal("a contact file under the wrong fingerprint must be rejected")
	}
}

// ---- Round trip ----------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 1024, ChunkSize - 1, ChunkSize, ChunkSize + 1,
		2 * ChunkSize, 2*ChunkSize + 7}

	for _, size := range sizes {
		dir := t.TempDir()
		store := trustingStore(t, dir, alice, "alice")
		data := make([]byte, size)
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("rand: %v", err)
		}
		pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
		out := filepath.Join(dir, "out.bin")
		result, err := openPkg(pkg, bob, store, out)
		if err != nil {
			t.Fatalf("size %d: OpenFile: %v", size, err)
		}
		if !bytes.Equal(mustRead(t, out), data) {
			t.Fatalf("size %d: plaintext mismatch", size)
		}
		if result.TotalBytes != int64(size) {
			t.Fatalf("size %d: reported %d bytes", size, result.TotalBytes)
		}
		want := int64((size + ChunkSize - 1) / ChunkSize)
		if want == 0 {
			want = 1
		}
		if result.ChunkCount != want {
			t.Fatalf("size %d: expected %d chunks, got %d", size, want, result.ChunkCount)
		}
		if result.SenderName != "alice" {
			t.Fatalf("size %d: sender reported as %q", size, result.SenderName)
		}
	}
}

func TestPackageIDsAndCiphertextsAreFresh(t *testing.T) {
	dir := t.TempDir()
	data := []byte("same plaintext every time")
	a := seal(t, dir, alice, bob.Public(), data, "a.albpkg")
	b := seal(t, dir, alice, bob.Public(), data, "b.albpkg")
	if bytes.Equal(mustRead(t, a), mustRead(t, b)) {
		t.Fatal("two packages of the same plaintext must differ")
	}
	ha, err := ParseHeader(mustRead(t, a)[:HeaderLen])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	hb, _ := ParseHeader(mustRead(t, b)[:HeaderLen])
	if bytes.Equal(ha.PackageID, hb.PackageID) {
		t.Fatal("package identifiers must be fresh")
	}
	if bytes.Equal(ha.KemCt, hb.KemCt) {
		t.Fatal("encapsulations must be fresh")
	}
}

func TestOpenBytes(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 5000)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	out := filepath.Join(dir, "out.bin")
	result, err := OpenBytes(mustRead(t, pkg), OpenOptions{
		Recipient:  bob,
		Contacts:   store,
		OutputPath: out,
		Overwrite:  true,
	})
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	if result.TotalBytes != int64(len(data)) || !bytes.Equal(mustRead(t, out), data) {
		t.Fatal("OpenBytes did not recover the plaintext")
	}
}

// ---- Trust enforcement on open ------------------------------------------

func TestWrongRecipientRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	pkg := seal(t, dir, alice, bob.Public(), []byte("for bob only"), "pkg.albpkg")
	_, err := openPkg(pkg, mallory, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryTrust)
}

func TestUnknownSenderRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	pkg := seal(t, dir, alice, bob.Public(), []byte("hello"), "pkg.albpkg")
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryTrust)
}

func TestUnverifiedSenderRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	if _, err := store.ImportContact("alice", alice.Public()); err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	pkg := seal(t, dir, alice, bob.Public(), []byte("hello"), "pkg.albpkg")
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryTrust)
}

func TestRevokedSenderRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	pkg := seal(t, dir, alice, bob.Public(), []byte("hello"), "pkg.albpkg")
	if _, err := store.Revoke("alice"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryTrust)
}

func TestSealingToUnverifiedContactRefused(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	contact, err := store.ImportContact("bob", bob.Public())
	if err != nil {
		t.Fatalf("ImportContact: %v", err)
	}
	source := filepath.Join(dir, "in.bin")
	mustWrite(t, source, []byte("x"))
	out := filepath.Join(dir, "out.albpkg")
	_, err = SealFile(SealOptions{
		Sender: alice, Recipient: contact, InputPath: source, OutputPath: out,
	})
	requireCategory(t, err, CategoryTrust)
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("no package may be written for an unverified contact")
	}
}

// ---- Tamper matrix -------------------------------------------------------

func TestHeaderTamperingRejected(t *testing.T) {
	offsets := map[string]int{
		"magic": 0, "format_version": 8, "suite_id": 10, "header_len": 15,
		"flags": 16, "chunk_size": 23, "sender_fpr": 24, "recipient_fpr": 56,
		"package_id": 88, "kem_ct_len": 105, "kem_ct": 110,
	}
	for field, offset := range offsets {
		dir := t.TempDir()
		store := trustingStore(t, dir, alice, "alice")
		data := make([]byte, 4096)
		rand.Read(data)
		pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
		mustWrite(t, pkg, flip(mustRead(t, pkg), offset))
		out := filepath.Join(dir, "out.bin")
		if _, err := openPkg(pkg, bob, store, out); err == nil {
			t.Fatalf("tampering with %s must be rejected", field)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("tampering with %s left an output file", field)
		}
	}
}

func TestSubstitutedEncapsulationRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 2048)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	blob := mustRead(t, pkg)
	kemKey, err := mallory.Public().KemKey()
	if err != nil {
		t.Fatalf("KemKey: %v", err)
	}
	_, other := kemKey.Encapsulate()
	copy(blob[8+2+2+4+4+4+32+32+16+2:], other)
	mustWrite(t, pkg, blob)

	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err == nil {
		t.Fatal("a substituted encapsulation must be rejected")
	}
}

func TestBadSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 2048)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	blob := mustRead(t, pkg)
	blob[len(blob)-SigTrailerLen-SigLen+10] ^= 0xff
	mustWrite(t, pkg, blob)

	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryAuth)
}

func TestSignatureFromAnotherSenderRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 1024)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	mustWrite(t, pkg, resign(t, mustRead(t, pkg), mallory))

	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryAuth)
}

func TestCiphertextTamperingRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 4096)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	mustWrite(t, pkg, flip(mustRead(t, pkg), HeaderLen+20))

	out := filepath.Join(dir, "out.bin")
	_, err := openPkg(pkg, bob, store, out)
	requireCategory(t, err, CategoryAuth)
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("a failed open must not leave an output file")
	}
}

func TestChunkReorderingRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 3*ChunkSize)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	blob := mustRead(t, pkg)
	rec := 5 + ChunkSize + AeadTagLen
	a0 := HeaderLen
	swapped := bytes.Clone(blob[:a0])
	swapped = append(swapped, blob[a0+rec:a0+2*rec]...)
	swapped = append(swapped, blob[a0:a0+rec]...)
	swapped = append(swapped, blob[a0+2*rec:]...)
	mustWrite(t, pkg, resign(t, swapped, alice))

	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryAuth)
}

func TestChunkTruncationRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 2*ChunkSize)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	blob := mustRead(t, pkg)
	rec := 5 + ChunkSize + AeadTagLen
	bodyLen := len(blob) - SigTrailerLen - SigLen
	completion := blob[bodyLen-CompletionLen : bodyLen]
	kept := append(bytes.Clone(blob[:HeaderLen+rec]), completion...)
	mustWrite(t, pkg, resign(t, kept, alice))

	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err == nil {
		t.Fatal("dropping a whole chunk must be rejected by the completion record")
	}
}

func TestByteTruncationAndAppendedDataRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 4096)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	good := mustRead(t, pkg)

	mustWrite(t, pkg, good[:len(good)-1])
	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err == nil {
		t.Fatal("a truncated package must be rejected")
	}

	mustWrite(t, pkg, append(bytes.Clone(good), []byte("extra")...))
	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err == nil {
		t.Fatal("appended data must be rejected")
	}
}

func TestNoncanonicalFramingRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	pkg := seal(t, dir, alice, bob.Public(), []byte("small"), "pkg.albpkg")
	good := mustRead(t, pkg)

	// A final marker that is neither 0 nor 1.
	blob := bytes.Clone(good)
	blob[HeaderLen] = 2
	mustWrite(t, pkg, resign(t, blob, alice))
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryFormat)

	// A chunk length beyond the chunk size.
	blob = bytes.Clone(good)
	copy(blob[HeaderLen+1:], encU32(0xffffffff))
	mustWrite(t, pkg, resign(t, blob, alice))
	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err == nil {
		t.Fatal("an oversized chunk length must be rejected")
	}

	// A noncanonical signature length in the trailer.
	blob = bytes.Clone(good)
	copy(blob[len(blob)-SigTrailerLen:], encU32(SigLen+1))
	mustWrite(t, pkg, blob)
	_, err = openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryFormat)

	// A damaged trailer magic.
	blob = bytes.Clone(good)
	blob[len(blob)-1] ^= 0xff
	mustWrite(t, pkg, blob)
	_, err = openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryFormat)
}

func TestCompletionRecordTamperingRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 1024)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	blob := mustRead(t, pkg)
	bodyLen := len(blob) - SigTrailerLen - SigLen
	blob[bodyLen-1] ^= 0x01
	mustWrite(t, pkg, resign(t, blob, alice))

	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryAuth)
}

func TestCrossPackageSplicingRejected(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	dataA := make([]byte, 2048)
	dataB := make([]byte, 2048)
	rand.Read(dataA)
	rand.Read(dataB)
	a := seal(t, dir, alice, bob.Public(), dataA, "a.albpkg")
	b := seal(t, dir, alice, bob.Public(), dataB, "b.albpkg")

	spliced := append(bytes.Clone(mustRead(t, a)[:HeaderLen]),
		mustRead(t, b)[HeaderLen:]...)
	target := filepath.Join(dir, "spliced.albpkg")
	mustWrite(t, target, resign(t, spliced, alice))

	_, err := openPkg(target, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryAuth)
}

// ---- Output safety -------------------------------------------------------

func TestDestinationPreservedOnFailure(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 4096)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	mustWrite(t, pkg, flip(mustRead(t, pkg), HeaderLen+30))

	out := filepath.Join(dir, "out.bin")
	mustWrite(t, out, []byte("PRECIOUS ORIGINAL"))
	if _, err := openPkg(pkg, bob, store, out); err == nil {
		t.Fatal("a tampered package must be rejected")
	}
	if string(mustRead(t, out)) != "PRECIOUS ORIGINAL" {
		t.Fatal("the destination file must be left untouched")
	}
}

func TestNoOverwriteWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	pkg := seal(t, dir, alice, bob.Public(), []byte("hello"), "pkg.albpkg")
	out := filepath.Join(dir, "out.bin")
	mustWrite(t, out, []byte("ORIGINAL"))

	_, err := OpenFile(OpenOptions{
		Recipient: bob, Contacts: store, InputPath: pkg, OutputPath: out,
	})
	requireCategory(t, err, CategoryIO)
	if string(mustRead(t, out)) != "ORIGINAL" {
		t.Fatal("the destination must be preserved without --overwrite")
	}
}

func TestNoTemporaryFilesLeftBehind(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 4096)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")
	if _, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin")); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestCancellationPublishesNothing(t *testing.T) {
	dir := t.TempDir()
	store := trustingStore(t, dir, alice, "alice")
	data := make([]byte, 2*ChunkSize)
	rand.Read(data)
	pkg := seal(t, dir, alice, bob.Public(), data, "pkg.albpkg")

	out := filepath.Join(dir, "out.bin")
	cancelled := errors.New("cancelled")
	_, err := OpenFile(OpenOptions{
		Recipient: bob, Contacts: store, InputPath: pkg, OutputPath: out,
		Overwrite: true,
		Progress: func(_, chunks int64) error {
			if chunks >= 1 {
				return cancelled
			}
			return nil
		},
	})
	if !errors.Is(err, cancelled) {
		t.Fatalf("expected the cancellation error, got %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a cancelled open must not publish an output file")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

// ---- Bounds and key derivation ------------------------------------------

func TestCheckedAddOverflow(t *testing.T) {
	if _, err := checkedAdd(1, 2, 100, "test"); err != nil {
		t.Fatalf("checkedAdd rejected a valid sum: %v", err)
	}
	if _, err := checkedAdd(60, 60, 100, "test"); err == nil {
		t.Fatal("checkedAdd must reject a sum over the limit")
	}
	if _, err := checkedAdd(-1, 2, 100, "test"); err == nil {
		t.Fatal("checkedAdd must reject negatives")
	}
}

func TestChunkKeysAreDistinctPerIndex(t *testing.T) {
	master := bytes.Repeat([]byte{1}, 32)
	hd := bytes.Repeat([]byte{2}, 32)
	seen := map[string]bool{}
	for i := int64(0); i < 64; i++ {
		key, err := DeriveChunkKey(master, hd, i)
		if err != nil {
			t.Fatalf("DeriveChunkKey: %v", err)
		}
		encoded := hex.EncodeToString(key)
		if seen[encoded] {
			t.Fatalf("chunk key repeated at index %d", i)
		}
		seen[encoded] = true
	}
}

func TestKeysBoundToHeaderDigest(t *testing.T) {
	ss := bytes.Repeat([]byte{3}, 32)
	a, _ := DeriveMaster(ss, bytes.Repeat([]byte{0}, 32))
	b, _ := DeriveMaster(ss, bytes.Repeat([]byte{1}, 32))
	if bytes.Equal(a, b) {
		t.Fatal("the master key must depend on the header digest")
	}
}

func TestCompletionKeyDiffersFromChunkKeys(t *testing.T) {
	master := bytes.Repeat([]byte{4}, 32)
	hd := bytes.Repeat([]byte{5}, 32)
	done, _ := DeriveCompletionKey(master, hd)
	for i := int64(0); i < 16; i++ {
		key, _ := DeriveChunkKey(master, hd, i)
		if bytes.Equal(done, key) {
			t.Fatalf("the completion key collides with chunk key %d", i)
		}
	}
}

func TestChunkIndexBounds(t *testing.T) {
	master := make([]byte, 32)
	hd := make([]byte, 32)
	if _, err := DeriveChunkKey(master, hd, -1); err == nil {
		t.Fatal("a negative chunk index must be rejected")
	}
	if _, err := DeriveChunkKey(master, hd, MaxChunks); err == nil {
		t.Fatal("a chunk index at the limit must be rejected")
	}
}

func TestPackageTooSmallRejected(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	pkg := filepath.Join(dir, "tiny.albpkg")
	mustWrite(t, pkg, make([]byte, 100))
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	requireCategory(t, err, CategoryFormat)
}

// ---- No secret leakage ---------------------------------------------------

func TestErrorsNeverContainKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	store := mustStore(t, dir)
	pkg := seal(t, dir, alice, bob.Public(), []byte("secret plaintext contents"), "pkg.albpkg")
	_, err := openPkg(pkg, bob, store, filepath.Join(dir, "out.bin"))
	if err == nil {
		t.Fatal("expected a trust failure")
	}
	text := err.Error()
	if strings.Contains(text, "secret plaintext") || strings.Contains(text, passphrase) {
		t.Fatal("an error message leaked sensitive material")
	}
}
