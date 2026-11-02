// ALBPKG/1 -- Go port.
//
// ML-KEM-768 comes from the Go standard library (crypto/mlkem, FIPS 203).
// ML-DSA-65 is not in the standard library at this Go version, so it comes
// from CIRCL, Cloudflare's maintained cryptographic library. Neither
// primitive is implemented here.
module github.com/alb/albpkg

go 1.26.0

require (
	github.com/cloudflare/circl v1.6.5
	golang.org/x/term v0.46.0
)

require golang.org/x/sys v0.48.0 // indirect
