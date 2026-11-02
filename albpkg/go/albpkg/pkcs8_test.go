package albpkg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPKCS8IdentityContainsTwoStandardObjects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err = SaveIdentity(identity, path, provider, false, 0); err != nil {
		t.Fatal(err)
	}
	kemEncrypted, sigEncrypted, err := parseIdentityPEM(mustRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte(passphrase)
	kemPlain, err := decryptPKCS8(kemEncrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	sigPlain, err := decryptPKCS8(sigEncrypted, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(kemPlain)
	defer wipe(sigPlain)
	kemSeed, err := parsePlainPKCS8(kemPlain, oidMLKEM768, KemSeedLen)
	if err != nil {
		t.Fatal(err)
	}
	sigSeed, err := parsePlainPKCS8(sigPlain, oidMLDSA65, SigSeedLen)
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(kemSeed)
	defer wipe(sigSeed)
	if !bytes.Equal(kemSeed, identity.kemSeed) || !bytes.Equal(sigSeed, identity.sigSeed) {
		t.Fatal("PKCS#8 seeds differ")
	}
}

func TestLegacyIdentityRequiresExplicitMigration(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.key")
	target := filepath.Join(dir, "identity.key")
	identity, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err = saveLegacyIdentity(identity, source, provider, false, 0); err != nil {
		t.Fatal(err)
	}
	original := mustRead(t, source)
	if _, err = LoadIdentity(source, provider); err == nil {
		t.Fatal("normal loader accepted legacy identity")
	}
	migrated, err := MigrateLegacyIdentity(source, target, provider, false)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if !bytes.Equal(original, mustRead(t, source)) {
		t.Fatal("migration changed the legacy source")
	}
	loaded, err := LoadIdentity(target, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if !FingerprintsEqual(loaded.Fingerprint(), identity.Fingerprint()) {
		t.Fatal("migration changed identity")
	}
}

func TestIdentityPEMRejectsCRLFAndTrailingData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.key")
	identity, _ := GenerateIdentity()
	defer identity.Close()
	if err := SaveIdentity(identity, path, provider, false, 0); err != nil {
		t.Fatal(err)
	}
	valid := mustRead(t, path)
	for _, bad := range [][]byte{append(bytes.Clone(valid), '\n'), bytes.ReplaceAll(valid, []byte("\n"), []byte("\r\n")), []byte("ALBPKSK2legacy")} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadIdentity(path, provider); err == nil {
			t.Fatal("accepted noncanonical or legacy identity")
		}
	}
}
