package albpkg

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func constantTimeBytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// randomHex returns n random bytes as hex, for unique temporary file names.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", wrapError(CategoryIO, err, "could not read from the system CSPRNG")
	}
	return hex.EncodeToString(buf), nil
}

// restrictPermissions makes path readable and writable by its owner only.
//
// On POSIX this is chmod 0600. On Windows we replace the DACL with a single
// ACE for the current user via icacls, disabling inheritance. A failure is
// surfaced rather than pretending the file is protected.
func restrictPermissions(path string) error {
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return wrapError(CategoryIO, err, "failed to restrict file permissions")
		}
		return nil
	}

	who, err := exec.Command("whoami", "/user", "/fo", "csv", "/nh").Output()
	if err != nil {
		return ioErrorf("cannot determine current user SID")
	}
	sid := regexp.MustCompile(`S-1-[0-9-]+`).Find(who)
	if len(sid) == 0 {
		return ioErrorf("cannot determine current user SID")
	}
	principal := "*" + string(sid)
	cmd := exec.Command("icacls", path, "/inheritance:r", "/grant:r", principal+":F")
	if out, err := cmd.CombinedOutput(); err != nil {
		return wrapError(CategoryIO, err, "failed to restrict file permissions: %s",
			strings.TrimSpace(string(out)))
	}
	return nil
}

// permissionsAreOwnerOnly is a best-effort check used before loading a key.
func permissionsAreOwnerOnly(path string) bool {
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			return false
		}
		return info.Mode().Perm()&0o077 == 0
	}
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, ":(") {
			continue
		}
		for _, shared := range []string{"Everyone", `BUILTIN\Users`, "Authenticated Users"} {
			if strings.Contains(line, shared) {
				return false
			}
		}
	}
	return true
}

// openPrivateNew creates path exclusively with owner-only permissions.
func openPrivateNew(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, err
		}
		return nil, wrapError(CategoryIO, err, "cannot create %s", filepath.Base(path))
	}
	if runtime.GOOS == "windows" {
		if err := restrictPermissions(path); err != nil {
			file.Close()
			os.Remove(path)
			return nil, err
		}
	}
	return file, nil
}

func tempSibling(destination string) (string, error) {
	suffix, err := randomHex(8)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(destination)
	base := filepath.Base(destination)
	return filepath.Join(dir, fmt.Sprintf(".%s.albpkg-%s.tmp", base, suffix)), nil
}

// withAtomicOutput runs body against a private temporary file and publishes it
// atomically on success.
//
// On any error the temporary file is removed and destination is left exactly as
// it was. Without overwrite, an existing destination fails before any work is
// done and is never touched.
func withAtomicOutput(destination string, overwrite bool, body func(*os.File) error) error {
	parent := filepath.Dir(destination)
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		return ioErrorf("destination directory does not exist: %s", parent)
	}
	if _, err := os.Stat(destination); err == nil && !overwrite {
		return ioErrorf("destination exists and overwrite was not requested: %s",
			filepath.Base(destination))
	}

	var (
		file *os.File
		temp string
	)
	for attempt := 0; attempt < 8; attempt++ {
		candidate, err := tempSibling(destination)
		if err != nil {
			return err
		}
		file, err = openPrivateNew(candidate)
		if err == nil {
			temp = candidate
			break
		}
		if !os.IsExist(err) {
			return err
		}
	}
	if file == nil {
		return ioErrorf("could not create a unique temporary file")
	}

	published := false
	defer func() {
		if !published {
			file.Close()
			os.Remove(temp)
		}
	}()

	if err := body(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return wrapError(CategoryIO, err, "could not flush the output file")
	}
	if err := file.Close(); err != nil {
		return wrapError(CategoryIO, err, "could not close the output file")
	}
	var publishErr error
	if overwrite {
		publishErr = os.Rename(temp, destination)
	} else {
		publishErr = os.Link(temp, destination)
		if publishErr == nil {
			_ = os.Remove(temp)
		}
	}
	if err := publishErr; err != nil {
		os.Remove(temp)
		return wrapError(CategoryIO, err, "could not publish the output file")
	}
	published = true
	return nil
}

// withPrivateSpool runs body against an owner-only scratch file that is always
// deleted.
func withPrivateSpool(directory string, body func(*os.File, string) error) error {
	suffix, err := randomHex(8)
	if err != nil {
		return err
	}
	temp := filepath.Join(directory, ".albpkg-spool-"+suffix+".tmp")
	file, err := openPrivateNew(temp)
	if err != nil {
		return err
	}
	defer func() {
		file.Close()
		os.Remove(temp)
	}()
	return body(file, temp)
}

// wipe overwrites a secret buffer in place.
//
// Go's garbage collector may have copied the backing array, and the bytes may
// be in swap, so this is best-effort like every managed runtime. It is still
// worth doing: it bounds how long the live copy stays readable.
func wipe(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
	runtime.KeepAlive(buf)
}
