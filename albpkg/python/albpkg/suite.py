"""Suite constants, limits, and the fail-closed provider check.

FORMAT.md section 1 and section 4.  Nothing here is configurable at runtime: a
build either supports ALBPKG-1 in full or refuses to load.
"""

from __future__ import annotations

from .errors import ProviderError

# ---- Suite ---------------------------------------------------------------

SUITE_ID = 0x0001
SUITE_NAME = "ALBPKG-1"
FORMAT_VERSION = 1

KEM_PUB_LEN = 1184
KEM_CT_LEN = 1088
KEM_SS_LEN = 32
KEM_SEED_LEN = 64
SIG_PUB_LEN = 1952
SIG_LEN = 3309
SIG_SEED_LEN = 32

AEAD_KEY_LEN = 32
AEAD_TAG_LEN = 16
AEAD_NONCE_LEN = 12
AEAD_NONCE = b"\x00" * AEAD_NONCE_LEN

FPR_LEN = 32
PACKAGE_ID_LEN = 16

# ---- Magics --------------------------------------------------------------

PUBID_MAGIC = b"ALBPKID1"
SKFILE_MAGIC = b"ALBPKSK2"

# Private identity container (FORMAT.md 2.4)
KDF_PBKDF2_SHA256 = 0x0001
KDF_SALT_LEN = 16
#: Written by this implementation.  Readers accept anything in the range.
KDF_ITERATIONS = 600_000
KDF_MIN_ITERATIONS = 600_000
KDF_MAX_ITERATIONS = 10_000_000
PACKAGE_MAGIC = b"ALBPKG1\x00"
SIG_TRAILER_MAGIC = b"ALBPKGSG"

PUBID_LEN = len(PUBID_MAGIC) + 2 + 2 + KEM_PUB_LEN + 2 + SIG_PUB_LEN  # 3150
HEADER_LEN = len(PACKAGE_MAGIC) + 2 + 2 + 4 + 4 + 4 + FPR_LEN * 2 + PACKAGE_ID_LEN + 2 + KEM_CT_LEN  # 1194

SIG_TRAILER_LEN = 4 + len(SIG_TRAILER_MAGIC)  # u32 sig_len || magic

# ---- Domain separation strings (ASCII, no trailing NUL) ------------------

INFO_MASTER = b"ALBPKG1 master v1"
INFO_CHUNK = b"ALBPKG1 chunk v1"
INFO_COMPLETE = b"ALBPKG1 complete v1"

AAD_CHUNK_PREFIX = b"ALBPKG1-CHUNK"
AAD_COMPLETE_PREFIX = b"ALBPKG1-COMPLETE"
SIG_CONTEXT = b"ALBPKG1-SIGV1"

# ---- Limits --------------------------------------------------------------

CHUNK_SIZE = 1 << 20  # 1 MiB
MAX_PLAINTEXT = 1 << 40  # 1 TiB
MAX_CHUNKS = MAX_PLAINTEXT // CHUNK_SIZE  # 1048576
CHUNK_FRAME_OVERHEAD = 1 + 4 + AEAD_TAG_LEN  # final || pt_len || tag
COMPLETION_LEN = 16 + AEAD_TAG_LEN
# Worst case on-the-wire size, used to bound spooling of non-seekable input.
MAX_PACKAGE_SIZE = (
    HEADER_LEN
    + MAX_CHUNKS * (CHUNK_SIZE + CHUNK_FRAME_OVERHEAD)
    + COMPLETION_LEN
    + SIG_LEN
    + SIG_TRAILER_LEN
)

UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def check_provider() -> None:
    """Fail closed unless every required primitive is available.

    Called at import time.  A partial provider is treated as no provider: we
    never silently substitute a different algorithm.
    """
    missing = []
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: F401

        if not hasattr(mlkem, "MLKEM768PrivateKey"):
            missing.append("ML-KEM-768")
    except Exception:  # pragma: no cover - provider-dependent
        missing.append("ML-KEM-768")

    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401

        if not hasattr(mldsa, "MLDSA65PrivateKey"):
            missing.append("ML-DSA-65")
    except Exception:  # pragma: no cover - provider-dependent
        missing.append("ML-DSA-65")

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        AESGCM(b"\x00" * AEAD_KEY_LEN)
    except Exception:  # pragma: no cover - provider-dependent
        missing.append("AES-256-GCM")

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF

        HKDF(algorithm=hashes.SHA256(), length=32, salt=b"\x00" * 32, info=b"x").derive(
            b"\x00" * 32
        )
    except Exception:  # pragma: no cover - provider-dependent
        missing.append("HKDF-SHA-256")

    if missing:
        raise ProviderError(
            "required algorithms unavailable from the cryptographic provider: "
            + ", ".join(missing)
        )


def assert_self_consistent() -> None:
    """Guard the compile-time constants against edit mistakes."""
    assert PUBID_LEN == 3150, PUBID_LEN
    assert HEADER_LEN == 1194, HEADER_LEN
    assert MAX_CHUNKS == 1048576, MAX_CHUNKS


assert_self_consistent()
