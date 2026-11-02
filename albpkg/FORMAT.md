# ALBPKG/1 — Signed Post-Quantum Package Format

Normative specification. Every port (C, C++, Rust, Go, Python, PHP, Pascal, TypeScript)
implements **this document**, independently. Ports MUST NOT share code and MUST NOT
reimplement any cryptographic primitive: all primitives come from a maintained provider
(OpenSSL 3.5 LTS EVP, Python `cryptography`, Go standard crypto, Node `crypto`).

This format is **unrelated to ALB_C512**. C512 is research-only. An ALBPKG implementation
MUST NOT contain, link, or fall back to any C512 code path.

## 0. Conventions

* All integers are **big-endian** and unsigned unless stated otherwise.
* `u8`, `u16`, `u32`, `u64` denote fixed-width big-endian integers.
* `||` is concatenation. `SHA256(x)` / `SHA512(x)` are FIPS 180-4.
* `HKDF(ikm, salt, info, L)` is HKDF-SHA-256 (RFC 5869), extract-then-expand, output `L` bytes.
* A field is **noncanonical** if it violates any stated length, range, or ordering rule.
  Parsers MUST reject noncanonical input rather than normalize it.

## 1. Suite

| id | name | KEM | Signature | KDF | AEAD |
|----|------|-----|-----------|-----|------|
| `0x0001` | `ALBPKG-1` | ML-KEM-768 | ML-DSA-65 | HKDF-SHA-256 | AES-256-GCM |

Constants: `KEM_PUB = 1184`, `KEM_CT = 1088`, `KEM_SS = 32`, `KEM_SEED = 64`,
`SIG_PUB = 1952`, `SIG_LEN = 3309`, `SIG_SEED = 32`, `AEAD_KEY = 32`,
`AEAD_TAG = 16`, `AEAD_NONCE = 12`.

Private-key encryption (§2.4) additionally uses PBES2 with
PBKDF2-HMAC-SHA-256 and AES-256-CBC.

An implementation MUST **fail closed** at load time if any of these algorithms is
unavailable from its provider. It MUST NOT substitute another algorithm.

## 2. Identity

An identity is a pair of independent keys: an ML-KEM-768 *encryption* key and an
ML-DSA-65 *signing* key. They are generated separately and never derived from one another.

### 2.1 Canonical public identity

```
PUBID := "ALBPKID1"          (8 bytes, ASCII, no NUL)
      || u16  suite_id       (= 0x0001)
      || u16  kem_pub_len    (= 1184)
      || kem_pub[kem_pub_len]
      || u16  sig_pub_len    (= 1952)
      || sig_pub[sig_pub_len]
```

Total length is exactly `8 + 2 + 2 + 1184 + 2 + 1952 = 3150` bytes. Any other length,
any other magic, or a length field disagreeing with the suite constants is noncanonical.

### 2.2 Fingerprint

```
FPR := SHA256(PUBID)            (32 bytes)
```

Displayed as 64 lowercase hex characters, grouped in 8 blocks of 8 separated by `-`:

```
1a2b3c4d-5e6f7081-....-....-....-....-....-........
```

The fingerprint covers **both** public keys. Verification of a contact is verification of
the whole 256-bit fingerprint over an out-of-band channel. Implementations MUST NOT offer
truncated-fingerprint comparison, and MUST compare fingerprints in constant time.

### 2.3 Public identity export file

UTF-8 text, LF line endings:

```
-----BEGIN ALBPKG PUBLIC IDENTITY-----
suite: ALBPKG-1
fingerprint: <64 hex>
<base64 of PUBID, wrapped at 64 columns>
-----END ALBPKG PUBLIC IDENTITY-----
```

On import the reader MUST re-derive the fingerprint from the decoded `PUBID` and reject
the file if it disagrees with the `fingerprint:` line.

### 2.4 Private identity file

The identity is a canonical UTF-8/LF PEM file containing two standard PKCS#8
`EncryptedPrivateKeyInfo` objects. File mode MUST be owner-only (`0600` on POSIX;
owner-only DACL on Windows). The first object is ML-KEM-768 and the second is
ML-DSA-65. Reversing, omitting, duplicating, or appending objects is noncanonical.

```
ALBPKG PRIVATE IDENTITY 1\n
-----BEGIN ENCRYPTED PRIVATE KEY-----\n
<base64 of encrypted ML-KEM-768 PKCS#8 DER, wrapped at 64 columns>\n
-----END ENCRYPTED PRIVATE KEY-----\n
-----BEGIN ENCRYPTED PRIVATE KEY-----\n
<base64 of encrypted ML-DSA-65 PKCS#8 DER, wrapped at 64 columns>\n
-----END ENCRYPTED PRIVATE KEY-----\n
```

The unencrypted `PrivateKeyInfo` carries only the standardized key-generation
seed as the context-specific `[0]` value (DER tag `0x80`) inside the PKCS#8
`privateKey` OCTET STRING. Its algorithm identifier is `id-ML-KEM-768`
(`2.16.840.1.101.3.4.4.2`) or
`id-ML-DSA-65` (`2.16.840.1.101.3.4.3.18`) with absent parameters. The seed is
exactly 64 or 32 bytes respectively. Expanded private keys are not serialized.

Each object is independently encrypted using PKCS#8 `EncryptedPrivateKeyInfo`:

* PBES2 (`1.2.840.113549.1.5.13`);
* PBKDF2 (`1.2.840.113549.1.5.12`) with a fresh 16-byte CSPRNG salt,
  600000 iterations, a 32-byte derived key, and explicit HMAC-SHA-256 PRF
  (`1.2.840.113549.2.9` with NULL parameters);
* AES-256-CBC (`2.16.840.1.101.3.4.1.42`) with a fresh 16-byte CSPRNG IV and
  PKCS#7 padding.

Readers accept iteration counts from 600000 through 10000000 and reject values
outside that range before performing PBKDF2. They reject unknown algorithms,
parameters, noncanonical DER, objects over 4096 bytes, noncanonical PEM,
trailing bytes, and a key in the wrong position. Writers always use 600000.
Wrong-passphrase and altered-ciphertext failures use the same error category.

The historical `ALBPKSK2` seed container is a legacy research artifact. Normal
identity loading MUST NOT autodetect or fall back to it. A separately named
`migrate-legacy-identity` operation may read it only when the operator supplies
an explicit source and a different destination. Migration never deletes or
overwrites the source.

Passphrases are obtained from an interactive no-echo prompt, a caller-supplied callback,
or a file descriptor. Implementations MUST NOT accept a passphrase as a command-line
argument and MUST NOT write one to a log.

### 2.5 Contact store

A contact is a stored `PUBID` plus a trust state:

* `unverified` — imported, fingerprint not yet confirmed. **Cannot open packages from it**
  and cannot be sealed to.
* `verified` — full fingerprint confirmed out of band.
* `revoked` — locally revoked. Always rejected.

Importing a `PUBID` for an existing fingerprint is a no-op. Importing a *different*
`PUBID` under a name already bound to another fingerprint is a **key replacement** and
MUST reset the trust state to `unverified`.

## 3. Package layout

```
PACKAGE := HEADER || CHUNK+ || COMPLETION || SIGBLOCK
```

Exactly one `COMPLETION` record, at least one `CHUNK` record.

### 3.1 Header

```
HEADER := "ALBPKG1\0"         (8 bytes)
       || u16  format_version (= 1)
       || u16  suite_id       (= 0x0001)
       || u32  header_len     (total byte length of HEADER, including this field)
       || u32  flags          (= 0; unknown bits rejected)
       || u32  chunk_size     (= 1048576)
       || sender_fpr[32]
       || recipient_fpr[32]
       || package_id[16]      (fresh CSPRNG per package)
       || u16  kem_ct_len     (= 1088)
       || kem_ct[kem_ct_len]
```

`header_len` MUST equal `8+2+2+4+4+4+32+32+16+2+1088 = 1194`. The header is
authenticated by being bound into every derived key (§3.2) and by the signature (§3.5).
Header fields are **not** confidential: sender and recipient fingerprints, package size,
and chunk size are visible to anyone holding the file.

```
HD := SHA256(HEADER)          (32 bytes)
```

### 3.2 Key derivation

Let `SS` be the 32-byte ML-KEM-768 shared secret (`Encapsulate(kem_pub_recipient)` for the
sender, `Decapsulate(kem_ct)` for the recipient).

```
MASTER      := HKDF(ikm = SS,     salt = HD, info = "ALBPKG1 master v1",   L = 32)
CHUNK_KEY_i := HKDF(ikm = MASTER, salt = HD, info = "ALBPKG1 chunk v1"  || u64 i, L = 32)
DONE_KEY    := HKDF(ikm = MASTER, salt = HD, info = "ALBPKG1 complete v1", L = 32)
```

`info` string literals are ASCII **without** a trailing NUL.

Because `HD` covers the sender fingerprint, recipient fingerprint, package identifier,
encapsulation, and framing parameters, every one of those is bound into every key: any
alteration makes every AEAD tag fail.

Every `CHUNK_KEY_i` and `DONE_KEY` is used for exactly **one** AES-256-GCM encryption.
The nonce is therefore the fixed 12 zero bytes. Implementations MUST NOT reuse a derived
key for a second encryption, and MUST NOT introduce a variable nonce.

### 3.3 Chunk record

Plaintext is split into chunks of exactly `chunk_size` bytes, except the last, which is
`1..chunk_size` bytes — or `0` bytes if and only if the input is empty (an empty input
produces exactly one final chunk of length 0).

```
CHUNK_i := u8  final          (0 or 1; 1 only for the last chunk)
        || u32 pt_len         (<= chunk_size; == chunk_size unless final == 1)
        || ct[pt_len + 16]    (AES-256-GCM ciphertext || tag)

AAD_i   := "ALBPKG1-CHUNK" || HD || u64 i || u32 pt_len || u8 final
ct      := AES-256-GCM(key = CHUNK_KEY_i, nonce = 0^12, aad = AAD_i, pt = chunk_i)
```

Indices start at 0 and increase by exactly 1. A reader MUST track the expected index and
reject a record whose framing implies any other index — reordering, duplication, or a gap
changes `CHUNK_KEY_i` and so fails authentication, and is additionally rejected by framing.

### 3.4 Completion record

```
COMPLETION := ct[16 + 16]

AAD_c := "ALBPKG1-COMPLETE" || HD || u64 total_bytes || u64 chunk_count
pt_c  := u64 total_bytes || u64 chunk_count
ct    := AES-256-GCM(key = DONE_KEY, nonce = 0^12, aad = AAD_c, pt = pt_c)
```

The reader recomputes `total_bytes` and `chunk_count` from what it actually decrypted and
uses those values to build `AAD_c` and to compare against `pt_c`. Truncation of whole
chunks therefore fails here even though each surviving chunk authenticates.

### 3.5 Signature block

Let `BODY := HEADER || CHUNK+ || COMPLETION` (every byte of the package before `SIGBLOCK`).

```
SIGMSG  := "ALBPKG1-SIGV1" || SHA512(BODY)
sig     := ML-DSA-65-Sign(sender_sig_priv, SIGMSG)

SIGBLOCK := sig[sig_len]
         || u32 sig_len
         || "ALBPKGSG"        (8 bytes)
```

The trailer is at a fixed offset from EOF so a reader can locate and verify the signature
before decrypting anything. Appended data moves the trailer and is rejected; altered body
bytes change `SHA512(BODY)` and fail verification.

## 4. Limits

| limit | value |
|-------|-------|
| max plaintext | 1 TiB (`1099511627776` bytes) |
| chunk size | 1 MiB (`1048576`) |
| max chunk count | `1048576` |
| max package size | max plaintext + framing + signature |
| recipients per package | 1 |

Counters are 64-bit. A reader MUST reject `chunk_count`, `total_bytes`, or an implied
offset exceeding these limits **before** allocating or reading, and MUST check every
length addition for overflow.

## 5. Sealing (`sealFile`)

1. Load sender private identity; load recipient contact. **Abort if the contact is not
   `verified`**, or is `revoked`.
2. `SS, kem_ct := Encapsulate(recipient.kem_pub)`; `package_id := CSPRNG(16)`.
3. Build `HEADER`, compute `HD`, derive `MASTER`.
4. Stream the input in `chunk_size` blocks, emitting `CHUNK_i`. Maintain `total_bytes`,
   `chunk_count`, and a running SHA-512 over every emitted byte.
5. Emit `COMPLETION`.
6. Sign and emit `SIGBLOCK`.
7. Output is written to a private temporary file in the destination directory and
   published atomically (§7).

## 6. Opening (`openFile`)

1. Read and validate `HEADER` (magic, version, suite, `header_len`, `flags`, `chunk_size`,
   `kem_ct_len`).
2. Resolve `sender_fpr` in the contact store. **Abort unless the contact is `verified`.**
   Abort if `recipient_fpr` is not this identity's fingerprint.
3. Locate `SIGBLOCK` from EOF, hash `BODY`, and **verify the ML-DSA-65 signature against
   the trusted sender before any decryption**. If the input is not seekable, spool at most
   the maximum package size to a private temporary file first, then proceed seekably.
4. Decapsulate, derive `MASTER`, and decrypt each chunk in order into a **private
   temporary file** in the destination directory.
5. Verify `COMPLETION` against the observed `total_bytes` / `chunk_count`.
6. Only after every tag, the completion record, and the signature have all verified,
   publish the temporary file atomically to the destination (§7).

At no point may a partially decrypted file appear at the destination path. On any failure
the temporary file is removed and the destination is left untouched.

## 7. Output publication

* The temporary file is created in the **destination directory** with owner-only mode and
  an `O_EXCL` fresh name.
* With explicit overwrite, publication atomically replaces the destination via
  the platform rename/replace operation.
* Without overwrite, publication uses a platform primitive that fails atomically
  if the destination already exists (for example `link()` followed by unlinking
  the temporary file, or `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`). A
  check-then-rename sequence is not sufficient. A destination created during
  processing is preserved.

## 8. Security properties

Provided:

* Confidentiality and integrity of the file contents against anyone but the recipient.
* Authentication of the sender, over the entire serialized package.
* Binding of sender, recipient, encapsulation, package identifier, and framing into every
  key, so cross-package splicing fails.
* Detection of reordering, duplication, truncation, and appended data.

**Not** provided, and not to be claimed:

* Forward secrecy. Compromise of a recipient's ML-KEM private key decrypts every past
  package sent to it.
* Replay prevention. The format is transport-independent; a whole valid package can be
  delivered twice. Callers needing replay protection must track `package_id` themselves.
* Metadata privacy. Sender and recipient fingerprints, the package identifier, chunk size,
  and the approximate plaintext size are all visible.
* Deniability.

## 9. Error handling

Errors are structured and MUST distinguish at least: `FORMAT` (framing/parse),
`UNSUPPORTED` (version/suite), `LIMIT` (bounds/overflow), `TRUST` (unknown, unverified, or
revoked contact; wrong recipient), `AUTH` (signature or AEAD tag failure), `IO`,
`PASSPHRASE`. Error messages MUST NOT contain key material, plaintext, or passphrases.

A reader MUST NOT report *where* an authentication failure occurred in a way that
distinguishes tag-by-tag position to an untrusted caller beyond the chunk index already
visible in the framing.
