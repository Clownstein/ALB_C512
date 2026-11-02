"""ALBPKG/1 — signed post-quantum file packages.

A separate product from ALB_C512.  Every primitive comes from the `cryptography`
package (OpenSSL under the hood): ML-KEM-768, ML-DSA-65, HKDF-SHA-256, and
AES-256-GCM.  No cryptographic primitive is implemented here, and there is no
code path that reaches ALB_C512.

See ``FORMAT.md`` for the normative wire format.
"""

from __future__ import annotations

from .contacts import Contact, ContactStore, Trust
from .errors import (
    AlbpkgError,
    AuthError,
    FormatError,
    IOErrorAlbpkg,
    LimitError,
    PassphraseError,
    ProviderError,
    TrustError,
    UnsupportedError,
)
from .identity import (
    Identity,
    PublicIdentity,
    export_public_identity,
    format_fingerprint,
    generate_identity,
    load_identity,
    migrate_legacy_identity,
    parse_fingerprint,
    save_identity,
)
from .package import (
    Header,
    OpenResult,
    SealResult,
    open_file,
    open_stream,
    seal_file,
)
from .suite import (
    CHUNK_SIZE,
    FORMAT_VERSION,
    MAX_PLAINTEXT,
    SUITE_ID,
    SUITE_NAME,
    check_provider,
)

__version__ = "1.0.0"

# Fail closed at import time if the provider cannot supply the suite.
check_provider()


def import_contact(store: ContactStore, name: str, armored: str) -> Contact:
    """Import an armored public identity into `store` as an unverified contact."""
    return store.import_contact(name, PublicIdentity.from_armored(armored))


def verify_contact(store: ContactStore, selector: str, fingerprint: str) -> Contact:
    """Mark a contact verified after a full out-of-band fingerprint match."""
    return store.verify_contact(selector, fingerprint)


__all__ = [
    "AlbpkgError",
    "AuthError",
    "CHUNK_SIZE",
    "Contact",
    "ContactStore",
    "FORMAT_VERSION",
    "FormatError",
    "Header",
    "IOErrorAlbpkg",
    "Identity",
    "LimitError",
    "MAX_PLAINTEXT",
    "OpenResult",
    "PassphraseError",
    "ProviderError",
    "PublicIdentity",
    "SUITE_ID",
    "SUITE_NAME",
    "SealResult",
    "Trust",
    "TrustError",
    "UnsupportedError",
    "__version__",
    "check_provider",
    "export_public_identity",
    "format_fingerprint",
    "generate_identity",
    "import_contact",
    "load_identity",
    "migrate_legacy_identity",
    "open_file",
    "open_stream",
    "parse_fingerprint",
    "save_identity",
    "seal_file",
    "verify_contact",
]
