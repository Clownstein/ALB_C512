# Security policy and status

## Do not use this repository for real information

No component in this repository is currently approved to protect real data.

* **C512, C512-Lite, C512-SIV, and C512-XOF are research fixtures.** Their
  central transform is many-to-one even though the historical design rationale
  called it a permutation. They are available only behind explicit research
  opt-in and must not be selected by production code.
* **`albpkg/` is a review candidate.** It uses ML-KEM-768, ML-DSA-65,
  HKDF-SHA-256, and AES-256-GCM from maintained providers and has no path to
  C512. Four of eight required ports are implemented. Independent
  cryptographic and per-port security review has not happened, so passing tests
  does not make it suitable for real information.

See [`REMEDIATION.md`](REMEDIATION.md) for evidence and
[`albpkg/RELEASE_STATUS.md`](albpkg/RELEASE_STATUS.md) for the current gate.

## Confirmed C512 defects

[`tools/c512_structural_regressions.py`](tools/c512_structural_regressions.py)
reproduces three structural collisions:

1. Chi over the 32-lane even ring maps an alternating lane pattern and its
   complement to the same output.
2. The butterfly maps zero and a nonzero half-state to the same output.
3. The cross-mix has a nonzero linear kernel.

C512-Lite inherits the Chi collision. These results invalidate the claimed
permutation construction. They do not constitute a complete plaintext-recovery
or tag-forgery attack, and this repository makes no claim that such an attack
has been demonstrated.

The collision regressions intentionally keep passing while the versioned
research algorithm is unchanged. Changing the transform would define another
unreviewed cipher and invalidate its vectors; it would not establish security.

## Claims this project does not make

C512 has no established IND-CPA, INT-CTXT, post-quantum, constant-time,
side-channel, or misuse-resistance result. Key length, NTT terminology,
avalanche measurements, entropy estimates, and statistical smoke tests do not
establish any of those properties. The library does not track nonce reuse.

The historical statement that `encrypt_with_nonce` tracks nonces was false. It
generates a random nonce for one call and stores no history. Reuse of a nonce
with the same C512 key is unsafe, but avoiding reuse would not repair the
structural design defects.

`albpkg/` does not claim forward secrecy, replay prevention, metadata privacy,
or deniability. Its exact intended properties and limits are in
[`albpkg/FORMAT.md`](albpkg/FORMAT.md).

## Safe research handling

* Set `ALB_C512_EXPERIMENTAL=1` or the language-specific research opt-in only
  for compatibility tests and cryptanalysis.
* Do not put production entry points, automatic format detection, or fallback
  behavior in front of C512.
* Do not log keys or plaintext hashes. Supply research keys through protected
  files or file descriptors, never command-line arguments.
* Use [`tools/migrate_c512_file.py`](tools/migrate_c512_file.py) only as an
  explicit one-way migration. It authenticates the bounded legacy artifact,
  retains the source, and seals the recovered plaintext as ALBPKG/1. This does
  not make the source cipher secure.

## Reporting a vulnerability

Report vulnerabilities privately through the repository owner's configured
security-reporting channel. The repository does not currently publish a valid
security email address or PGP key, so this document does not invent one or
promise response times that have not been operationally established.

Include the affected file and version, prerequisites, impact, and a minimal
reproduction when possible. Do not include real secrets or personal data.

## Release rule

A release recommendation for real information requires all of the following:

* all eight independent ALBPKG ports and all 64 producer/consumer pairs;
* required malformed-input, large-file, fault, cleanup, permission, fuzz, and
  sanitizer gates on Windows and Linux;
* pinned and audited final providers and reproducible source archives; and
* independent review of the package construction and every production port.

The release tool fails closed while those conditions remain incomplete.
