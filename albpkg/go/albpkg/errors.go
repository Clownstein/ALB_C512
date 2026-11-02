// Package albpkg implements ALBPKG/1, a signed post-quantum package format.
//
// This is an independent implementation of albpkg/FORMAT.md. It shares no code
// with the Python or TypeScript ports; the three are tested against each other
// by albpkg/interop/run_interop.py.
//
// Primitives come from maintained providers only: ML-KEM-768 from the Go
// standard library's crypto/mlkem (FIPS 203), ML-DSA-65 from CIRCL, and
// AES-256-GCM, HKDF-SHA-256, PBKDF2-HMAC-SHA-256, SHA-256 and SHA-512 from the
// standard library. No cryptographic primitive is implemented in this package.
//
// ALBPKG is unrelated to ALB_C512. There is no code path from here to C512 and
// no fallback to it.
package albpkg

import "fmt"

// Category classifies a failure. FORMAT.md section 9 requires these to be
// distinguishable by the caller.
type Category string

const (
	CategoryFormat      Category = "FORMAT"
	CategoryUnsupported Category = "UNSUPPORTED"
	CategoryLimit       Category = "LIMIT"
	CategoryTrust       Category = "TRUST"
	CategoryAuth        Category = "AUTH"
	CategoryIO          Category = "IO"
	CategoryPassphrase  Category = "PASSPHRASE"
	CategoryProvider    Category = "PROVIDER"
)

// Error is the structured error type every exported function returns.
//
// Messages must never carry key material, plaintext, or passphrases.
type Error struct {
	Cat     Category
	Message string
	Wrapped error
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s", e.Cat, e.Message)
}

func (e *Error) Unwrap() error { return e.Wrapped }

// Is reports whether target is an *Error of the same category, so callers can
// write errors.Is(err, albpkg.ErrAuth).
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other.Cat == e.Cat && other.Message == ""
}

func newError(cat Category, format string, args ...any) *Error {
	return &Error{Cat: cat, Message: fmt.Sprintf(format, args...)}
}

func wrapError(cat Category, cause error, format string, args ...any) *Error {
	return &Error{Cat: cat, Message: fmt.Sprintf(format, args...), Wrapped: cause}
}

// Sentinel values for errors.Is checks.
var (
	ErrFormat      = &Error{Cat: CategoryFormat}
	ErrUnsupported = &Error{Cat: CategoryUnsupported}
	ErrLimit       = &Error{Cat: CategoryLimit}
	ErrTrust       = &Error{Cat: CategoryTrust}
	ErrAuth        = &Error{Cat: CategoryAuth}
	ErrIO          = &Error{Cat: CategoryIO}
	ErrPassphrase  = &Error{Cat: CategoryPassphrase}
	ErrProvider    = &Error{Cat: CategoryProvider}
)

func formatErrorf(format string, args ...any) *Error {
	return newError(CategoryFormat, format, args...)
}

func unsupportedErrorf(format string, args ...any) *Error {
	return newError(CategoryUnsupported, format, args...)
}

func limitErrorf(format string, args ...any) *Error {
	return newError(CategoryLimit, format, args...)
}

func trustErrorf(format string, args ...any) *Error {
	return newError(CategoryTrust, format, args...)
}

func authErrorf(format string, args ...any) *Error {
	return newError(CategoryAuth, format, args...)
}

func ioErrorf(format string, args ...any) *Error {
	return newError(CategoryIO, format, args...)
}

func passphraseErrorf(format string, args ...any) *Error {
	return newError(CategoryPassphrase, format, args...)
}
