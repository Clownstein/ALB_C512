package albpkg

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Trust is a contact's trust state (FORMAT.md 2.5).
type Trust string

const (
	// TrustUnverified means imported but not yet confirmed out of band. Such a
	// contact cannot be sealed to and packages from it are refused.
	TrustUnverified Trust = "unverified"
	// TrustVerified means the full 256-bit fingerprint was confirmed.
	TrustVerified Trust = "verified"
	// TrustRevoked means locally revoked; always rejected.
	TrustRevoked Trust = "revoked"
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$`)

// ValidateName checks a contact name.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return formatErrorf(
			"contact name must be 1-64 characters of [A-Za-z0-9._@+-] starting " +
				"with an alphanumeric")
	}
	return nil
}

// Contact is a stored public identity plus its trust state.
type Contact struct {
	Name   string
	Public *PublicIdentity
	Trust  Trust
}

// Fingerprint returns the contact's fingerprint.
func (c *Contact) Fingerprint() []byte { return c.Public.Fingerprint() }

// FingerprintText returns the grouped display form.
func (c *Contact) FingerprintText() string { return c.Public.FingerprintText() }

// RequireUsable returns an error unless this contact may be sealed to or
// accepted from.
func (c *Contact) RequireUsable() error {
	if c.Trust == TrustRevoked {
		return trustErrorf("contact '%s' is revoked", c.Name)
	}
	if c.Trust != TrustVerified {
		return trustErrorf(
			"contact '%s' is unverified; confirm the full fingerprint %s out of "+
				"band and run 'verify-contact' first", c.Name, c.FingerprintText())
	}
	return nil
}

// contactRecord is the on-disk JSON shape. Field order in the struct is
// irrelevant: the keys are emitted sorted, matching the other ports byte for
// byte.
type contactRecord struct {
	Name    string `json:"name"`
	PubID   string `json:"pubid"`
	Trust   string `json:"trust"`
	Version int    `json:"version"`
}

// ContactStore is a directory of one JSON file per contact, keyed by
// fingerprint.
//
// Keyed by fingerprint rather than by name so a name collision can never
// silently substitute one key for another; the name is a field in the record.
type ContactStore struct {
	Directory string
}

// NewContactStore opens (creating if needed) a contact directory.
func NewContactStore(directory string) (*ContactStore, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, wrapError(CategoryIO, err, "cannot create the contact directory")
	}
	return &ContactStore{Directory: directory}, nil
}

func (s *ContactStore) pathFor(fpr []byte) string {
	return filepath.Join(s.Directory, hex.EncodeToString(fpr)+".contact")
}

func (s *ContactStore) loadFile(path string) (*Contact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot read contact file %s",
			filepath.Base(path))
	}
	if info.Size() > maxContactFileBytes {
		return nil, formatErrorf("contact file %s is implausibly large",
			filepath.Base(path))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot read contact file %s",
			filepath.Base(path))
	}

	// Reject unknown fields rather than ignoring them: a field we do not
	// understand may be the one carrying the meaning.
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var record contactRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, formatErrorf("contact file %s is not a valid record",
			filepath.Base(path))
	}
	if record.Version != 1 {
		return nil, formatErrorf("unsupported contact record version in %s",
			filepath.Base(path))
	}
	if err := ValidateName(record.Name); err != nil {
		return nil, err
	}
	trust := Trust(record.Trust)
	switch trust {
	case TrustUnverified, TrustVerified, TrustRevoked:
	default:
		return nil, formatErrorf("unknown trust state in %s", filepath.Base(path))
	}

	pubid, err := base64.StdEncoding.DecodeString(record.PubID)
	if err != nil {
		return nil, formatErrorf("contact file %s has a malformed key",
			filepath.Base(path))
	}
	public, err := PublicIdentityFromPubID(pubid)
	if err != nil {
		return nil, err
	}
	if filepath.Base(path) != hex.EncodeToString(public.Fingerprint())+".contact" {
		return nil, formatErrorf(
			"contact file %s does not match its own key fingerprint",
			filepath.Base(path))
	}

	return &Contact{Name: record.Name, Public: public, Trust: trust}, nil
}

func (s *ContactStore) write(contact *Contact) error {
	record := contactRecord{
		Name:    contact.Name,
		PubID:   base64.StdEncoding.EncodeToString(contact.Public.PubID()),
		Trust:   string(contact.Trust),
		Version: 1,
	}
	// Keys are emitted in sorted order to match the Python and TypeScript
	// ports byte for byte.
	blob, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return wrapError(CategoryIO, err, "could not encode the contact record")
	}
	blob = append(blob, '\n')

	return withAtomicOutput(s.pathFor(contact.Fingerprint()), true, func(file *os.File) error {
		return writeAll(file, blob)
	})
}

// Get returns the contact with this fingerprint, or nil if there is none.
func (s *ContactStore) Get(fpr []byte) (*Contact, error) {
	path := s.pathFor(fpr)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	return s.loadFile(path)
}

// Require returns the contact with this fingerprint or a trust error.
func (s *ContactStore) Require(fpr []byte) (*Contact, error) {
	contact, err := s.Get(fpr)
	if err != nil {
		return nil, err
	}
	if contact == nil {
		text, _ := FormatFingerprint(fpr)
		return nil, trustErrorf(
			"no contact for fingerprint %s; import and verify it first", text)
	}
	return contact, nil
}

// List returns every stored contact, sorted by name then fingerprint.
func (s *ContactStore) List() ([]*Contact, error) {
	entries, err := os.ReadDir(s.Directory)
	if err != nil {
		return nil, wrapError(CategoryIO, err, "cannot read the contact directory")
	}
	var contacts []*Contact
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".contact") {
			continue
		}
		contact, err := s.loadFile(filepath.Join(s.Directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, contact)
	}
	sort.Slice(contacts, func(i, j int) bool {
		if contacts[i].Name != contacts[j].Name {
			return contacts[i].Name < contacts[j].Name
		}
		return hex.EncodeToString(contacts[i].Fingerprint()) <
			hex.EncodeToString(contacts[j].Fingerprint())
	})
	return contacts, nil
}

// ByName resolves a unique contact name.
func (s *ContactStore) ByName(name string) (*Contact, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	var matches []*Contact
	for _, contact := range all {
		if contact.Name == name {
			matches = append(matches, contact)
		}
	}
	if len(matches) == 0 {
		return nil, trustErrorf("no contact named '%s'", name)
	}
	if len(matches) > 1 {
		return nil, trustErrorf(
			"'%s' is bound to %d different keys; resolve it by fingerprint",
			name, len(matches))
	}
	return matches[0], nil
}

// Resolve accepts a fingerprint (grouped or plain hex) or a contact name.
func (s *ContactStore) Resolve(selector string) (*Contact, error) {
	if fpr, err := ParseFingerprint(selector); err == nil {
		return s.Require(fpr)
	}
	return s.ByName(selector)
}

// ImportContact stores a public identity under name, always as unverified.
//
// Re-importing the identical key preserves the existing trust state. Importing
// a different key under a name already bound elsewhere is a key replacement:
// the new key is stored unverified and the old one is demoted, so a stale
// verified key can never be selected by name.
func (s *ContactStore) ImportContact(name string, public *PublicIdentity) (*Contact, error) {
	return s.importContactWithWriter(name, public, s.write)
}

// importContactWithWriter lets fault tests stop at either durable write.
func (s *ContactStore) importContactWithWriter(name string, public *PublicIdentity, write func(*Contact) error) (*Contact, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	existing, err := s.Get(public.Fingerprint())
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.Name != name {
			return nil, trustErrorf(
				"this key is already stored as '%s'; remove it before importing "+
					"it under a different name", existing.Name)
		}
		return existing, nil
	}

	all, err := s.List()
	if err != nil {
		return nil, err
	}
	contact := &Contact{Name: name, Public: public, Trust: TrustUnverified}
	for _, old := range all {
		if old.Name == name && old.Trust != TrustRevoked {
			demoted := &Contact{Name: old.Name, Public: old.Public, Trust: TrustUnverified}
			if err := write(demoted); err != nil {
				return nil, err
			}
		}
	}
	// Demote old fingerprints before publishing the replacement so a failed
	// write cannot leave a newly imported key beside a verified old key.
	if err := write(contact); err != nil {
		return nil, err
	}
	return contact, nil
}

// VerifyContact marks a contact verified, but only on a full fingerprint match.
func (s *ContactStore) VerifyContact(selector, presented string) (*Contact, error) {
	contact, err := s.Resolve(selector)
	if err != nil {
		return nil, err
	}
	expected, err := ParseFingerprint(presented)
	if err != nil {
		return nil, err
	}
	if !FingerprintsEqual(expected, contact.Fingerprint()) {
		return nil, trustErrorf(
			"the fingerprint you entered does not match the stored key; " +
				"the contact remains unverified")
	}
	if contact.Trust == TrustRevoked {
		return nil, trustErrorf(
			"contact '%s' is revoked; un-revoke it deliberately before verifying",
			contact.Name)
	}
	updated := &Contact{Name: contact.Name, Public: contact.Public, Trust: TrustVerified}
	if err := s.write(updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// SetTrust replaces a contact's trust state.
func (s *ContactStore) SetTrust(selector string, trust Trust) (*Contact, error) {
	contact, err := s.Resolve(selector)
	if err != nil {
		return nil, err
	}
	updated := &Contact{Name: contact.Name, Public: contact.Public, Trust: trust}
	if err := s.write(updated); err != nil {
		return nil, err
	}
	return updated, nil
}

// Revoke locally revokes a contact.
func (s *ContactStore) Revoke(selector string) (*Contact, error) {
	return s.SetTrust(selector, TrustRevoked)
}

// Remove deletes a contact record.
func (s *ContactStore) Remove(selector string) (*Contact, error) {
	contact, err := s.Resolve(selector)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(s.pathFor(contact.Fingerprint())); err != nil {
		return nil, wrapError(CategoryIO, err, "cannot remove the contact record")
	}
	return contact, nil
}
