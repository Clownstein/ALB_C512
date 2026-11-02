# ALBPKG C review candidate

This is an independent ALBPKG/1 framing implementation using OpenSSL EVP for
every cryptographic primitive. It does not use C512. It is incomplete and has
not received independent security review; do not deploy it for real information.

Implemented: in-memory identity generation/import, strict two-object encrypted
PKCS#8 identity persistence, public identity export, contact
import/fingerprint verification/revocation, and bounded file sealing and
opening. Opening takes a private encrypted snapshot and verifies its signature
before decryption. Publication refuses to replace an existing destination. C
and Python load each other's identity files in the interoperability test.

The real CLI is integrated into the main matrix. It uses bounded canonical
public-key parsing, owner-only identity/contact creation, SID-based key-file
permission validation on Windows, explicit trust transitions, and thread-local
structured API errors. ASan/UBSan identity and package round-trips pass locally.

Still required: Linux validation, allocation/I/O fault injection, parser
fuzzing, broader sanitizer runs, hostile-directory ACL review, and independent
security review.

Compile against OpenSSL 3.5 or later. Define `ALB_OPENSSL_HEADERS` when using the
provider's installed headers. `openssl_abi.h` contains public ABI declarations
for environments with the provider library but no development headers; it
contains no cryptographic implementation. Windows also requires `advapi32`.
The provider must expose both ML-KEM-768 and ML-DSA-65; missing algorithms fail.

The Python interoperability test requires the package's Python dependencies:

```
python test_interop.py /absolute/path/to/albpkg_c.dll /path/to/provider/dlls
```

On Linux the second argument is unnecessary. The test covers both directions
at empty, single-byte, chunk-boundary, and two-chunk lengths; public identities;
untrusted/revoked recipients; signed malformed frames; altered signatures;
cancellation; cleanup; and no-clobber publication including a late-created
destination. Passing these checks is not evidence of cryptographic security.
