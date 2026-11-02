# albpkg — signed post-quantum file packages

**Incomplete review candidate: do not deploy for real information.** The
eight-port implementation, encrypted PKCS#8 identity storage in the remaining
ports, full release acceptance, and independent security review are still
outstanding. Python, TypeScript, Go, and C now use the same strict two-object
encrypted PKCS#8 profile through their real CLIs. The four unwritten ports
still need the profile.

`albpkg` encrypts a file for exactly one verified contact and signs the whole
package. It is a **separate product from ALB_C512** and shares no code with it.
There is no code path from `albpkg` to C512 and no fallback to it.

| | |
|---|---|
| Key encapsulation | ML-KEM-768 |
| Signature | ML-DSA-65 |
| Key derivation | HKDF-SHA-256 |
| Bulk encryption | AES-256-GCM, 1 MiB chunks |
| Max file size | 1 TiB |
| Recipients | 1 per package |

Every primitive comes from a maintained provider: OpenSSL through Python's
`cryptography`, OpenSSL through Node's built-in `crypto`, the Go standard
library plus CIRCL for Go, and OpenSSL 3.5 LTS EVP in the remaining ports.
**No primitive is implemented in this repository.** If a provider cannot supply
the full suite, that port fails to load rather than substituting anything.

The normative wire format is [FORMAT.md](FORMAT.md). Every port implements that
document independently — no shared code, no generated bindings. That is the
point: four independent readings of the spec that agree byte for byte is
evidence the spec is unambiguous, which one implementation could never give.

## Status

| port | provider | state |
|---|---|---|
| Python | `cryptography` (locally OpenSSL 4.0.2) | candidate — 101 acceptance tests passed |
| TypeScript (Node) | Node `crypto` | candidate — 88 acceptance tests passed |
| Go | stdlib `crypto/mlkem` + CIRCL `mldsa65` | candidate — acceptance suite passed |
| C | OpenSSL 3.5.7 EVP | CLI/API candidate — package, trust, rejection, encrypted-PKCS#8, and explicit migration checks passed |
| C++, Rust, PHP, Pascal | planned OpenSSL 3.5 LTS EVP | not yet written |

**Cross-port interoperability is verified**, not assumed: all 16 of the 16
producer/consumer combinations among the four CLI candidates pass, across
payloads of 0 bytes, 1 byte, 1 KiB, and every chunk boundary through
2 MiB + 7 — plus identity exchange, fingerprint agreement, a shared rejection
matrix, all sixteen encrypted-PKCS#8 private-identity load pairs, and
source-preserving legacy identity migration in each CLI.
The quick profile currently comprises 180 checks, including explicit legacy
identity migration in every completed CLI; the full profile additionally
tests the one-byte and wider boundary set:

```bash
python albpkg/interop/run_interop.py --ports python,typescript,c,go
```

The release gate is 64 combinations across eight ports. Sixteen of those 64 are
covered. Run the harness with `--require` to make the four missing ports fail
the run rather than quietly narrow it:

```bash
python albpkg/interop/run_interop.py --require python,typescript,go,c,cpp,rust,php,pascal
```

**Not yet cleared for real data.** Passing tests is not the release gate. The
construction in FORMAT.md and each production port still need independent
cryptographic and security review — see [the remediation
record](../REMEDIATION.md) for what remains.
The current focused review also found that Python, Go, and TypeScript do not
adequately validate Windows private-file ACLs. Their Windows identity storage
must not be used for real information until native, handle-bound ACL handling
is implemented and tested. Contact replacement in those three ports was
changed to demote old trust before publishing a new key and has fault-point
regressions.

## Install

**Python** (3.10+):

```bash
python -m pip install -e albpkg/python
```

**TypeScript** (Node 24+, which runs the sources directly — no build step):

```bash
node albpkg/typescript/src/cli.ts --help
```

**Go** (1.24+):

```bash
go build -o bin/albpkg ./cmd/albpkg
```

Exact tested dependency versions are pinned in
[`python/requirements-frozen.txt`](python/requirements-frozen.txt) and
[`go/go.sum`](go/go.sum). The TypeScript port has **no dependencies at all** —
everything comes from `node:crypto`.

## Use

Alice and Bob each create an identity. Each identity is two independent keys —
one for encryption, one for signing — and the fingerprint covers both.

```bash
albpkg generate-identity
albpkg export-public-identity alice.pub
```

They exchange the `.pub` files by any means, then confirm the **full 64-character
fingerprint** over a channel they already trust — a phone call, in person, an
existing authenticated session. Nothing is usable until they do:

```bash
albpkg import-contact bob bob.pub
# prints the fingerprint; compare all 64 characters, then:
albpkg verify-contact bob 1a2b3c4d-5e6f7081-...
```

Then seal and open:

```bash
albpkg seal report.pdf report.albpkg --to bob
albpkg open report.albpkg report.pdf
```

Passphrases are never accepted as command-line arguments. The CLI prompts
without echo, or reads from `--passphrase-fd` or `ALBPKG_PASSPHRASE_FILE`.

## What it guarantees

* Only the named recipient can read the file.
* The package is authenticated end to end as coming from a sender you have
  verified — signature checked **before** anything is decrypted.
* Sender, recipient, encapsulation, package identifier, and framing are bound
  into every derived key, so pieces of different packages cannot be spliced.
* Reordering, duplication, truncation, and appended bytes are all detected.
* The destination file is published atomically, only after every check passes.
  A failed or cancelled `open` never leaves a partial file behind and never
  touches an existing destination.

## What it does not guarantee

* **No forward secrecy.** If a recipient's ML-KEM private key is compromised,
  every past package sent to it can be decrypted.
* **No replay prevention.** A whole valid package can be delivered twice. The
  format is transport-independent; track `package_id` yourself if you need this.
* **No metadata privacy.** Sender and recipient fingerprints, the package
  identifier, and the approximate file size are visible to anyone with the file.
* **No deniability.** The signature is the point.

## Trust model

An imported contact is `unverified` and cannot be sealed to or accepted from.
Only a full fingerprint match promotes it to `verified`. Truncated-fingerprint
comparison is not offered anywhere in the API or the CLI. If a contact's key is
replaced, trust resets to `unverified` and must be re-established. A locally
`revoked` contact is always rejected.

## Testing

```bash
python -m pytest albpkg/python/tests -q
node --test albpkg/typescript/tests/
cd albpkg/go && go test ./...
python albpkg/interop/run_interop.py --ports python,typescript,go
```

The suite covers round-trips at every chunk boundary including empty files, and
explicit rejection of: wrong recipients, unknown, unverified, and revoked
senders, every header field tampered individually, substituted encapsulations,
forged and mismatched signatures, altered ciphertext, reordered chunks,
duplicated chunks, dropped chunks, byte truncation, appended data, moved final
markers, oversized and noncanonical lengths, cross-package splicing, and
arithmetic overflow — plus destination preservation, cancellation, temp-file
cleanup, and the absence of secrets in logs and errors.
