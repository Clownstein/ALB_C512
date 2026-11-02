"""Identities: key generation, canonical public encoding, fingerprints, storage.

FORMAT.md section 2.  The encryption key (ML-KEM-768) and the signing key
(ML-DSA-65) are generated independently and neither is derived from the other.
The fingerprint covers both.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_der_private_key,
)

from . import suite
from .errors import (
    AuthError,
    FormatError,
    IOErrorAlbpkg,
    LimitError,
    PassphraseError,
    UnsupportedError,
)
from .fsutil import atomic_output, permissions_are_owner_only, restrict_permissions, wipe
from .pkcs8 import DEFAULT_ITERATIONS, decrypt_private_key_info, encrypt_private_key_info
from .wire import ByteReader, u16, u32

PassphraseProvider = Callable[[str], str]

_PEM_BEGIN = "-----BEGIN ALBPKG PUBLIC IDENTITY-----"
_PEM_END = "-----END ALBPKG PUBLIC IDENTITY-----"

MIN_PASSPHRASE_LEN = 8


# ---- Fingerprints --------------------------------------------------------


def fingerprint_of(pubid: bytes) -> bytes:
    """SHA-256 over the canonical public identity."""
    return hashlib.sha256(pubid).digest()


def format_fingerprint(fpr: bytes) -> str:
    """64 lowercase hex characters in eight dash-separated groups of eight."""
    if len(fpr) != suite.FPR_LEN:
        raise FormatError("fingerprint must be 32 bytes")
    hexed = fpr.hex()
    return "-".join(hexed[i : i + 8] for i in range(0, 64, 8))


def parse_fingerprint(text: str) -> bytes:
    """Accept grouped or ungrouped hex.  The full 256 bits are required."""
    cleaned = "".join(ch for ch in text.strip().lower() if ch not in "- :\t")
    if len(cleaned) != 64:
        raise FormatError(
            "a fingerprint is 64 hex characters; truncated fingerprints are not accepted"
        )
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise FormatError("fingerprint is not valid hex") from exc


def fingerprints_equal(a: bytes, b: bytes) -> bool:
    """Constant-time fingerprint comparison."""
    return hmac.compare_digest(a, b)


# ---- Canonical public identity ------------------------------------------


def encode_pubid(kem_pub: bytes, sig_pub: bytes) -> bytes:
    if len(kem_pub) != suite.KEM_PUB_LEN:
        raise FormatError("ML-KEM-768 public key has the wrong length")
    if len(sig_pub) != suite.SIG_PUB_LEN:
        raise FormatError("ML-DSA-65 public key has the wrong length")
    return b"".join(
        [
            suite.PUBID_MAGIC,
            u16(suite.SUITE_ID),
            u16(suite.KEM_PUB_LEN),
            kem_pub,
            u16(suite.SIG_PUB_LEN),
            sig_pub,
        ]
    )


def decode_pubid(data: bytes) -> tuple[bytes, bytes]:
    """Strictly decode a canonical public identity into (kem_pub, sig_pub)."""
    if len(data) != suite.PUBID_LEN:
        raise FormatError(
            f"public identity must be exactly {suite.PUBID_LEN} bytes, got {len(data)}"
        )
    reader = ByteReader(data, "public identity")
    reader.expect(suite.PUBID_MAGIC, "public identity magic")
    suite_id = reader.u16("suite id")
    if suite_id != suite.SUITE_ID:
        raise UnsupportedError(f"unsupported suite id 0x{suite_id:04x}")
    kem_len = reader.u16("kem public key length")
    if kem_len != suite.KEM_PUB_LEN:
        raise FormatError("noncanonical ML-KEM public key length")
    kem_pub = reader.take(kem_len, "kem public key")
    sig_len = reader.u16("signature public key length")
    if sig_len != suite.SIG_PUB_LEN:
        raise FormatError("noncanonical ML-DSA public key length")
    sig_pub = reader.take(sig_len, "signature public key")
    reader.finish()
    return kem_pub, sig_pub


# ---- Public identity -----------------------------------------------------


@dataclass(frozen=True)
class PublicIdentity:
    """A contact's public half: both keys plus the derived fingerprint."""

    kem_public_bytes: bytes
    sig_public_bytes: bytes

    @property
    def pubid(self) -> bytes:
        return encode_pubid(self.kem_public_bytes, self.sig_public_bytes)

    @property
    def fingerprint(self) -> bytes:
        return fingerprint_of(self.pubid)

    @property
    def fingerprint_text(self) -> str:
        return format_fingerprint(self.fingerprint)

    def kem_key(self) -> mlkem.MLKEM768PublicKey:
        return mlkem.MLKEM768PublicKey.from_public_bytes(self.kem_public_bytes)

    def sig_key(self) -> mldsa.MLDSA65PublicKey:
        return mldsa.MLDSA65PublicKey.from_public_bytes(self.sig_public_bytes)

    @classmethod
    def from_pubid(cls, data: bytes) -> "PublicIdentity":
        kem_pub, sig_pub = decode_pubid(data)
        return cls(kem_pub, sig_pub)

    # -- armored export/import --

    def to_armored(self) -> str:
        body = base64.b64encode(self.pubid).decode("ascii")
        wrapped = "\n".join(body[i : i + 64] for i in range(0, len(body), 64))
        return (
            f"{_PEM_BEGIN}\n"
            f"suite: {suite.SUITE_NAME}\n"
            f"fingerprint: {self.fingerprint.hex()}\n"
            f"{wrapped}\n"
            f"{_PEM_END}\n"
        )

    @classmethod
    def from_armored(cls, text: str) -> "PublicIdentity":
        lines = [ln.strip() for ln in text.replace("\r\n", "\n").split("\n")]
        lines = [ln for ln in lines if ln]
        if not lines or lines[0] != _PEM_BEGIN or lines[-1] != _PEM_END:
            raise FormatError("not an ALBPKG public identity file")
        declared_fpr: Optional[str] = None
        b64_parts: list[str] = []
        for line in lines[1:-1]:
            lowered = line.lower()
            if lowered.startswith("suite:"):
                if line.split(":", 1)[1].strip() != suite.SUITE_NAME:
                    raise UnsupportedError("unsupported suite in public identity file")
            elif lowered.startswith("fingerprint:"):
                if declared_fpr is not None:
                    raise FormatError("duplicate fingerprint header")
                declared_fpr = line.split(":", 1)[1].strip().lower()
            elif ":" in line and not _looks_like_base64(line):
                raise FormatError("unknown header in public identity file")
            else:
                b64_parts.append(line)
        if declared_fpr is None:
            raise FormatError("public identity file has no fingerprint header")
        try:
            raw = base64.b64decode("".join(b64_parts), validate=True)
        except Exception as exc:
            raise FormatError("public identity body is not valid base64") from exc
        identity = cls.from_pubid(raw)
        if not fingerprints_equal(identity.fingerprint, parse_fingerprint(declared_fpr)):
            raise FormatError(
                "public identity fingerprint header does not match the encoded keys"
            )
        return identity


def _looks_like_base64(line: str) -> bool:
    return all(c.isalnum() or c in "+/=" for c in line)


# ---- Private identity ----------------------------------------------------


@dataclass
class Identity:
    """A local identity holding both private keys."""

    kem_private: mlkem.MLKEM768PrivateKey
    sig_private: mldsa.MLDSA65PrivateKey

    @property
    def public(self) -> PublicIdentity:
        return PublicIdentity(
            self.kem_private.public_key().public_bytes_raw(),
            self.sig_private.public_key().public_bytes_raw(),
        )

    @property
    def fingerprint(self) -> bytes:
        return self.public.fingerprint


def generate_identity() -> Identity:
    """Generate a fresh, independent encryption key and signing key."""
    suite.check_provider()
    return Identity(
        kem_private=mlkem.MLKEM768PrivateKey.generate(),
        sig_private=mldsa.MLDSA65PrivateKey.generate(),
    )


def prompt_passphrase(prompt: str, *, confirm: bool = False) -> str:
    """No-echo terminal prompt.  Never a command-line argument, never logged."""
    try:
        value = getpass.getpass(f"{prompt}: ")
    except (EOFError, OSError) as exc:
        raise PassphraseError("no interactive terminal available for a passphrase") from exc
    if confirm:
        again = getpass.getpass(f"{prompt} (confirm): ")
        if again != value:
            raise PassphraseError("passphrases did not match")
    return value


def _resolve_passphrase(
    provider: Optional[PassphraseProvider], prompt: str, *, confirm: bool
) -> bytes:
    if provider is None:
        text = prompt_passphrase(prompt, confirm=confirm)
    else:
        text = provider(prompt)
    if not isinstance(text, str) or not text:
        raise PassphraseError("an empty passphrase is not accepted")
    if len(text) < MIN_PASSPHRASE_LEN:
        raise PassphraseError(
            f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        )
    return text.encode("utf-8")


def _derive_kek(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA-256 over the passphrase (FORMAT.md 2.4)."""
    return PBKDF2HMAC(
        algorithm=SHA256(), length=32, salt=salt, iterations=iterations
    ).derive(passphrase)


def _encode_seeds(kem_seed: bytes, sig_seed: bytes) -> bytes:
    return b"".join(
        [u16(len(kem_seed)), kem_seed, u16(len(sig_seed)), sig_seed]
    )


def _decode_seeds(blob: bytes) -> tuple[bytes, bytes]:
    reader = ByteReader(blob, "identity seeds")
    kem_len = reader.u16("kem seed length")
    if kem_len != suite.KEM_SEED_LEN:
        raise FormatError("noncanonical ML-KEM seed length")
    kem_seed = reader.take(kem_len, "kem seed")
    sig_len = reader.u16("signing seed length")
    if sig_len != suite.SIG_SEED_LEN:
        raise FormatError("noncanonical ML-DSA seed length")
    sig_seed = reader.take(sig_len, "signing seed")
    reader.finish()
    return kem_seed, sig_seed


def _save_legacy_identity(
    identity: Identity,
    path: Path,
    *,
    passphrase_provider: Optional[PassphraseProvider] = None,
    overwrite: bool = False,
    iterations: int = suite.KDF_ITERATIONS,
) -> None:
    """Write the passphrase-encrypted private identity with owner-only mode.

    A fresh salt is drawn on every write, which is what makes the fixed
    all-zero GCM nonce safe: the key encryption key is never reused.
    """
    path = Path(path)
    if not suite.KDF_MIN_ITERATIONS <= iterations <= suite.KDF_MAX_ITERATIONS:
        raise LimitError(
            f"iteration count must be between {suite.KDF_MIN_ITERATIONS} and "
            f"{suite.KDF_MAX_ITERATIONS}"
        )

    secret = _resolve_passphrase(
        passphrase_provider, f"Passphrase for {path.name}", confirm=True
    )

    pubid = identity.public.pubid
    salt = os.urandom(suite.KDF_SALT_LEN)
    prefix = b"".join(
        [
            suite.SKFILE_MAGIC,
            u16(suite.SUITE_ID),
            u16(suite.KDF_PBKDF2_SHA256),
            u32(iterations),
            salt,
            u32(len(pubid)),
            pubid,
        ]
    )

    seeds = bytearray(
        _encode_seeds(
            identity.kem_private.private_bytes_raw(),
            identity.sig_private.private_bytes_raw(),
        )
    )
    kek = bytearray(_derive_kek(secret, salt, iterations))
    try:
        sealed = AESGCM(bytes(kek)).encrypt(
            suite.AEAD_NONCE, bytes(seeds), prefix
        )
    finally:
        wipe(kek)
        wipe(seeds)

    blob = prefix + u32(len(sealed)) + sealed
    with atomic_output(path, overwrite=overwrite) as handle:
        handle.write(blob)
    restrict_permissions(path)


#: Generous bound on the sealed seed blob; the real one is 108 bytes.
MAX_SEALED_LEN = 1 << 12


def _load_legacy_identity(
    path: Path, *, passphrase_provider: Optional[PassphraseProvider] = None
) -> Identity:
    """Load and decrypt a private identity file, validating it strictly."""
    suite.check_provider()
    path = Path(path)
    try:
        with path.open("rb") as handle:
            blob = handle.read((1 << 16) + 1)
    except OSError as exc:
        raise IOErrorAlbpkg(f"cannot read identity file {path.name}") from exc

    if len(blob) > 1 << 16:
        raise LimitError("identity file exceeds 64 KiB")
    if not permissions_are_owner_only(path):
        raise IOErrorAlbpkg(
            f"identity file {path.name} is readable by others; "
            "fix its permissions before use"
        )

    reader = ByteReader(blob, "identity file")
    reader.expect(suite.SKFILE_MAGIC, "identity file magic")
    suite_id = reader.u16("suite id")
    if suite_id != suite.SUITE_ID:
        raise UnsupportedError(f"unsupported suite id 0x{suite_id:04x}")

    kdf_id = reader.u16("kdf id")
    if kdf_id != suite.KDF_PBKDF2_SHA256:
        raise UnsupportedError(f"unsupported key derivation function 0x{kdf_id:04x}")

    iterations = reader.u32("iteration count")
    if not suite.KDF_MIN_ITERATIONS <= iterations <= suite.KDF_MAX_ITERATIONS:
        raise LimitError(
            f"iteration count {iterations} is outside the permitted range "
            f"[{suite.KDF_MIN_ITERATIONS}, {suite.KDF_MAX_ITERATIONS}]"
        )

    salt = reader.take(suite.KDF_SALT_LEN, "salt")

    pubid_len = reader.u32("public identity length")
    if pubid_len != suite.PUBID_LEN:
        raise FormatError("noncanonical public identity length in identity file")
    pubid = reader.take(pubid_len, "public identity")
    stored_public = PublicIdentity.from_pubid(pubid)

    prefix_len = reader.offset
    sealed_len = reader.u32("sealed length")
    if not 0 < sealed_len <= MAX_SEALED_LEN:
        raise LimitError(f"implausible sealed seed length {sealed_len}")
    sealed = reader.take(sealed_len, "sealed seeds")
    reader.finish()

    secret = _resolve_passphrase(
        passphrase_provider, f"Passphrase for {path.name}", confirm=False
    )

    kek = bytearray(_derive_kek(secret, salt, iterations))
    try:
        try:
            seeds = AESGCM(bytes(kek)).decrypt(
                suite.AEAD_NONCE, sealed, blob[:prefix_len]
            )
        except Exception as exc:
            # Wrong passphrase and a tampered file are indistinguishable here,
            # which is the correct behaviour: both mean "do not proceed".
            raise PassphraseError(
                "could not decrypt the identity file; the passphrase is wrong "
                "or the file has been altered"
            ) from exc
    finally:
        wipe(kek)

    seed_buf = bytearray(seeds)
    try:
        kem_seed, sig_seed = _decode_seeds(bytes(seed_buf))
        try:
            kem_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(kem_seed)
            sig_private = mldsa.MLDSA65PrivateKey.from_seed_bytes(sig_seed)
        except Exception as exc:
            raise FormatError("identity file seeds are not valid keys") from exc
    finally:
        wipe(seed_buf)

    identity = Identity(kem_private, sig_private)
    if not fingerprints_equal(identity.fingerprint, stored_public.fingerprint):
        raise AuthError(
            "identity file seeds do not reproduce its stored public identity"
        )
    return identity


_IDENTITY_PREAMBLE = b"ALBPKG PRIVATE IDENTITY 1\n"
_PKCS8_BEGIN = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
_PKCS8_END = b"-----END ENCRYPTED PRIVATE KEY-----\n"


def _pem_pkcs8(der: bytes) -> bytes:
    body = base64.b64encode(der)
    wrapped = b"\n".join(body[i : i + 64] for i in range(0, len(body), 64))
    return _PKCS8_BEGIN + wrapped + b"\n" + _PKCS8_END


def _take_pem_pkcs8(blob: bytes, offset: int) -> tuple[bytes, int]:
    if not blob.startswith(_PKCS8_BEGIN, offset):
        raise FormatError("identity file is missing an encrypted PKCS#8 object")
    body_start = offset + len(_PKCS8_BEGIN)
    end = blob.find(_PKCS8_END, body_start)
    if end < 0:
        raise FormatError("identity file has an unterminated encrypted PKCS#8 object")
    encoded = blob[body_start:end]
    if not encoded.endswith(b"\n"):
        raise FormatError("noncanonical encrypted PKCS#8 PEM")
    lines = encoded[:-1].split(b"\n")
    if not lines or any(not line or len(line) > 64 for line in lines):
        raise FormatError("noncanonical encrypted PKCS#8 PEM wrapping")
    if any(len(line) != 64 for line in lines[:-1]):
        raise FormatError("noncanonical encrypted PKCS#8 PEM wrapping")
    try:
        der = base64.b64decode(b"".join(lines), validate=True)
    except ValueError as exc:
        raise FormatError("invalid encrypted PKCS#8 base64") from exc
    if _pem_pkcs8(der) != blob[offset : end + len(_PKCS8_END)]:
        raise FormatError("noncanonical encrypted PKCS#8 PEM encoding")
    return der, end + len(_PKCS8_END)


def _parse_identity_pem(blob: bytes) -> tuple[bytes, bytes]:
    if not blob.startswith(_IDENTITY_PREAMBLE):
        raise FormatError("unsupported private identity format")
    kem_der, offset = _take_pem_pkcs8(blob, len(_IDENTITY_PREAMBLE))
    sig_der, offset = _take_pem_pkcs8(blob, offset)
    if offset != len(blob):
        raise FormatError("trailing bytes in private identity file")
    return kem_der, sig_der


def save_identity(
    identity: Identity,
    path: Path,
    *,
    passphrase_provider: Optional[PassphraseProvider] = None,
    overwrite: bool = False,
    iterations: int = DEFAULT_ITERATIONS,
) -> None:
    """Store both private keys as passphrase-encrypted PKCS#8 objects."""
    path = Path(path)
    secret = bytearray(
        _resolve_passphrase(
            passphrase_provider, f"Passphrase for {path.name}", confirm=True
        )
    )
    try:
        kem_plain = identity.kem_private.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        sig_plain = identity.sig_private.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        kem_der = encrypt_private_key_info(kem_plain, bytes(secret), iterations=iterations)
        sig_der = encrypt_private_key_info(sig_plain, bytes(secret), iterations=iterations)
        blob = _IDENTITY_PREAMBLE + _pem_pkcs8(kem_der) + _pem_pkcs8(sig_der)
        with atomic_output(path, overwrite=overwrite) as handle:
            handle.write(blob)
        restrict_permissions(path)
    finally:
        wipe(secret)


def load_identity(
    path: Path, *, passphrase_provider: Optional[PassphraseProvider] = None
) -> Identity:
    """Load the canonical two-object encrypted PKCS#8 identity PEM.

    Legacy ALBPKSK2 is intentionally not autodetected. Use
    :func:`migrate_legacy_identity` with an explicit source path.
    """
    suite.check_provider()
    path = Path(path)
    try:
        with path.open("rb") as handle:
            blob = handle.read((1 << 16) + 1)
    except OSError as exc:
        raise IOErrorAlbpkg(f"cannot read identity file {path.name}") from exc
    if len(blob) > 1 << 16:
        raise LimitError("identity file exceeds 64 KiB")
    if not permissions_are_owner_only(path):
        raise IOErrorAlbpkg(
            f"identity file {path.name} is readable by others; fix its permissions before use"
        )
    kem_encrypted, sig_encrypted = _parse_identity_pem(blob)
    secret = bytearray(
        _resolve_passphrase(
            passphrase_provider, f"Passphrase for {path.name}", confirm=False
        )
    )
    try:
        kem_plain = bytearray(decrypt_private_key_info(kem_encrypted, bytes(secret)))
        sig_plain = bytearray(decrypt_private_key_info(sig_encrypted, bytes(secret)))
        try:
            kem_key = load_der_private_key(bytes(kem_plain), password=None)
            sig_key = load_der_private_key(bytes(sig_plain), password=None)
        except (TypeError, ValueError) as exc:
            raise FormatError("decrypted PKCS#8 object is not a valid private key") from exc
        finally:
            wipe(kem_plain)
            wipe(sig_plain)
    finally:
        wipe(secret)
    if not isinstance(kem_key, mlkem.MLKEM768PrivateKey):
        raise FormatError("first PKCS#8 object is not an ML-KEM-768 private key")
    if not isinstance(sig_key, mldsa.MLDSA65PrivateKey):
        raise FormatError("second PKCS#8 object is not an ML-DSA-65 private key")
    return Identity(kem_key, sig_key)


def migrate_legacy_identity(
    source: Path,
    target: Path,
    *,
    passphrase_provider: Optional[PassphraseProvider] = None,
    overwrite: bool = False,
) -> Identity:
    """Explicitly migrate ALBPKSK2 without deleting or replacing the source."""
    identity = _load_legacy_identity(
        Path(source), passphrase_provider=passphrase_provider
    )
    save_identity(
        identity,
        Path(target),
        passphrase_provider=passphrase_provider,
        overwrite=overwrite,
    )
    return identity


def export_public_identity(
    identity: Identity | PublicIdentity, path: Path, *, overwrite: bool = False
) -> str:
    """Write the armored public identity and return its fingerprint text."""
    public = identity.public if isinstance(identity, Identity) else identity
    armored = public.to_armored()
    with atomic_output(Path(path), overwrite=overwrite) as handle:
        handle.write(armored.encode("utf-8"))
    if os.name != "nt":
        os.chmod(path, 0o644)
    return public.fingerprint_text


__all__ = [
    "Identity",
    "PublicIdentity",
    "decode_pubid",
    "encode_pubid",
    "export_public_identity",
    "fingerprint_of",
    "fingerprints_equal",
    "format_fingerprint",
    "generate_identity",
    "load_identity",
    "migrate_legacy_identity",
    "parse_fingerprint",
    "prompt_passphrase",
    "save_identity",
]
