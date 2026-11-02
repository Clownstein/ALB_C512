"""Structured errors for ALBPKG/1.

Error messages must never carry key material, plaintext, or passphrases.  Each
class corresponds to one of the categories required by FORMAT.md section 9.
"""

from __future__ import annotations


class AlbpkgError(Exception):
    """Base class for every ALBPKG failure."""

    category = "ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.category}] {super().__str__()}"


class FormatError(AlbpkgError):
    """Framing or parse failure: bad magic, bad lengths, trailing bytes."""

    category = "FORMAT"


class UnsupportedError(AlbpkgError):
    """Unknown format version, suite id, or flag bits."""

    category = "UNSUPPORTED"


class LimitError(AlbpkgError):
    """A declared or implied length exceeds a bound, or an addition overflows."""

    category = "LIMIT"


class TrustError(AlbpkgError):
    """Unknown, unverified, or revoked contact; or wrong recipient."""

    category = "TRUST"


class AuthError(AlbpkgError):
    """Signature verification or AEAD tag verification failed."""

    category = "AUTH"


class IOErrorAlbpkg(AlbpkgError):
    """Filesystem or stream failure."""

    category = "IO"


class PassphraseError(AlbpkgError):
    """Passphrase missing, rejected, or unreadable."""

    category = "PASSPHRASE"


class ProviderError(AlbpkgError):
    """A required primitive is unavailable from the cryptographic provider."""

    category = "PROVIDER"


__all__ = [
    "AlbpkgError",
    "FormatError",
    "UnsupportedError",
    "LimitError",
    "TrustError",
    "AuthError",
    "IOErrorAlbpkg",
    "PassphraseError",
    "ProviderError",
]
