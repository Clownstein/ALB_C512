# Release gate status — 2026-09-22

**Not release eligible. Do not use this project to protect real information.**

The current security-readiness work focuses on the four implemented ports:
C, Go, Python, and TypeScript. This focus does not approve a four-port release.
The accepted design is being implemented in `albpkg/`. The competing
`secure/` prototype was removed after the user approved consolidation.
ALBPKG/1 is the single package wire format. C512 remains research-only.

## Verified locally

- Python's 101-test suite, TypeScript's 88-test suite, and the Go acceptance
  suite pass. The four-port quick CLI interoperability run passes 180 checks
  across all 16 Python/TypeScript/C/Go producer/consumer combinations,
  including all 16 encrypted-PKCS#8 private-identity pairs and explicit,
  source-preserving legacy migration in every CLI.
- C's independent EVP implementation exchanges packages with Python in both
  directions at 0, 1, 1 MiB minus 1, 1 MiB, 1 MiB plus 1, and 2 MiB bytes.
  Signed malformed frames, tampering, cancellation, contact trust, cleanup, and
  publication races are covered. C and Python also load each other's canonical
  two-object encrypted PKCS#8 identity files. This is additional API-level
  coverage. The C CLI is now enrolled in the main harness, uses protected
  passphrase sources, persists trust state, and reports thread-local structured
  API errors. Its ASan/UBSan identity and package round-trip also passes.
- Research Python canonical and negative fixtures: 103 checks pass. C/C++
  self-tests pass. The new C checked-API test covers capacity, aliasing,
  overflowing lengths, authentication cleanup, and injected allocation failure.
  The C self-test and checked-API regression also pass on 32-bit Windows.
- TypeScript's non-echoing passphrase prompt has an output-capture regression.
- Three research CLI regressions verify opt-in, key retention, secret-free
  output, and preservation of existing key files.
- No-clobber publication uses an atomic operation in Python, TypeScript, Go,
  and C. File opening snapshots ciphertext before signature verification and
  decryption. Python tests cover replacement of the original during opening.
- Identity file reads in Python, TypeScript, Go, and C are bounded to 64 KiB.
- Python, TypeScript, and Go now demote an old verified fingerprint before
  publishing a replacement contact. Each suite includes a failed-publication
  regression proving the old fingerprint is unverified after that failure.
- Explicit source-preserving `ALBPKSK2` identity migration is implemented in
  the C CLI and joins Python, TypeScript, and Go. It validates the legacy frame,
  authenticates the private seeds, reconstructs and compares the public
  fingerprint, then writes encrypted PKCS#8 without deleting the source.
- The bounded C512 demo-file migration is a Python-only compatibility tool. It
  requires an explicit `--experimental` acknowledgement and protected key
  source; it retains the original and writes through the separate ALBPKG/1
  package path. Production open commands do not detect or fall back to C512.
- Release tooling requires all eight ports and refuses release creation while
  independent review remains incomplete. Dry runs are named UNVALIDATED-SOURCE
  and explicitly report that they are not release eligible.

Local providers include Python cryptography 50.0.1 with OpenSSL 4.0.2 and the C
candidate linked to OpenSSL 3.5.7. These are distinct provider configurations;
one does not establish validation of the other. The C compiler used was the
project-local Zig 0.15.2 distribution.

## Required before completion

- **Resolve the Windows private-file ACL defect in the three managed ports.**
  `icacls /grant:r` leaves unrelated explicit ACEs in place, while the current
  loader check rejects only three English account names. A disposable Windows
  file with a `BUILTIN\\Administrators` read ACE passed that predicate. Private
  file creation and validation need native, handle-bound owner-only DACLs and
  tests in shared directories. Until then, Windows private identity handling
  is not suitable for protecting real information.
- Complete an independent cryptographic review of the ALBPKG/1 composition and
  an independent security review of each port intended for real-data use.
  The focused audit of the four implemented ports found two issues and did not
  fully review the 55-path `albpkg/` source inventory; it is not a substitute.
- Implement independent C++, Rust, PHP, and Pascal package ports.
- Implement the approved passphrase-encrypted PKCS#8 storage in the four
  unwritten ports. Python, TypeScript, Go, and C require explicit legacy
  migration and never fall back to ALBPKSK2 after a production parser failure.
- Complete equivalent APIs and CLIs in the four missing ports. Explicit,
  source-preserving migration exists for both ALBPKSK2 identities and bounded
  C512 demo artifacts; the four missing ports still need identity migration.
- Run all 64 combinations, multi-gigabyte and 1 TiB boundary checks, memory
  measurements, fault injection, fuzzing, sanitizers, crash cleanup, and Windows
  and Linux validation. Delphi runtime acceptance requires its compiler.
- Complete research vector execution in every port, including 32-bit/endian
  validation where claimed. Historical security documentation is marked
  withdrawn and points to the current research-only policy; it is not security
  evidence.
- Review Windows ACL creation and validation in every port, including localized
  systems and hostile directory access. C creates private files with a
  protected DACL and checks the already-open key handle's owner SID against the
  current process user; broader ACL review remains open. Managed ports still
  need equivalent native-handle review.
- Pin and audit final providers and release toolchains, verify source archives,
  and complete independent cryptographic and per-port security reviews.

No complete cryptanalysis, external review, forward-secrecy guarantee, replay
prevention, or reliable managed-runtime erasure is claimed. Passing the tests
above does not close any remaining release gate.
