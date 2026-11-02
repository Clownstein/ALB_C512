package albpkg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOversizedIdentityRejectedBeforePassphrase(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "oversized")
	if err := os.WriteFile(filename, make([]byte, 65537), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentity(filename, func(string) (string, error) {
		t.Fatal("oversized identity requested a passphrase")
		return "", nil
	})
	if err == nil {
		t.Fatal("accepted oversized identity")
	}
}
