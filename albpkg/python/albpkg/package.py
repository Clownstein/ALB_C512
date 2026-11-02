"""Package sealing and opening.

FORMAT.md sections 3, 5, and 6.  Streaming throughout: memory use is bounded by
one chunk (1 MiB) plus framing regardless of file size, and nothing partially
decrypted is ever visible at the destination path.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import suite
from .contacts import Contact, ContactStore
from .errors import (
    AuthError,
    FormatError,
    IOErrorAlbpkg,
    LimitError,
    TrustError,
    UnsupportedError,
)
from .fsutil import atomic_output, private_spool, wipe
from .identity import Identity, PublicIdentity, fingerprints_equal, format_fingerprint
from .wire import ByteReader, checked_add, is_seekable, read_exact, u16, u32, u64, u8

ProgressHook = Callable[[int, int], None]
"""Called as (bytes_done, chunks_done).  May raise to cancel the operation."""


# ---- Header --------------------------------------------------------------


@dataclass(frozen=True)
class Header:
    sender_fpr: bytes
    recipient_fpr: bytes
    package_id: bytes
    kem_ct: bytes
    chunk_size: int = suite.CHUNK_SIZE
    flags: int = 0

    def serialize(self) -> bytes:
        if len(self.sender_fpr) != suite.FPR_LEN:
            raise FormatError("sender fingerprint must be 32 bytes")
        if len(self.recipient_fpr) != suite.FPR_LEN:
            raise FormatError("recipient fingerprint must be 32 bytes")
        if len(self.package_id) != suite.PACKAGE_ID_LEN:
            raise FormatError("package identifier must be 16 bytes")
        if len(self.kem_ct) != suite.KEM_CT_LEN:
            raise FormatError("ML-KEM-768 encapsulation has the wrong length")
        if self.chunk_size != suite.CHUNK_SIZE:
            raise UnsupportedError("only a 1 MiB chunk size is defined for ALBPKG-1")
        if self.flags != 0:
            raise UnsupportedError("no header flags are defined for ALBPKG-1")

        blob = b"".join(
            [
                suite.PACKAGE_MAGIC,
                u16(suite.FORMAT_VERSION),
                u16(suite.SUITE_ID),
                u32(suite.HEADER_LEN),
                u32(self.flags),
                u32(self.chunk_size),
                self.sender_fpr,
                self.recipient_fpr,
                self.package_id,
                u16(suite.KEM_CT_LEN),
                self.kem_ct,
            ]
        )
        if len(blob) != suite.HEADER_LEN:
            raise FormatError("internal: header serialization length mismatch")
        return blob

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.serialize()).digest()

    @classmethod
    def parse(cls, blob: bytes) -> "Header":
        if len(blob) != suite.HEADER_LEN:
            raise FormatError(
                f"header must be exactly {suite.HEADER_LEN} bytes, got {len(blob)}"
            )
        r = ByteReader(blob, "package header")
        r.expect(suite.PACKAGE_MAGIC, "package magic")

        version = r.u16("format version")
        if version != suite.FORMAT_VERSION:
            raise UnsupportedError(f"unsupported format version {version}")
        suite_id = r.u16("suite id")
        if suite_id != suite.SUITE_ID:
            raise UnsupportedError(f"unsupported suite id 0x{suite_id:04x}")

        header_len = r.u32("header length")
        if header_len != suite.HEADER_LEN:
            raise FormatError("noncanonical header length")

        flags = r.u32("flags")
        if flags != 0:
            raise UnsupportedError(f"unknown header flag bits set: 0x{flags:08x}")

        chunk_size = r.u32("chunk size")
        if chunk_size != suite.CHUNK_SIZE:
            raise UnsupportedError(f"unsupported chunk size {chunk_size}")

        sender_fpr = r.take(suite.FPR_LEN, "sender fingerprint")
        recipient_fpr = r.take(suite.FPR_LEN, "recipient fingerprint")
        package_id = r.take(suite.PACKAGE_ID_LEN, "package identifier")

        kem_ct_len = r.u16("encapsulation length")
        if kem_ct_len != suite.KEM_CT_LEN:
            raise FormatError("noncanonical encapsulation length")
        kem_ct = r.take(kem_ct_len, "encapsulation")
        r.finish()

        return cls(
            sender_fpr=sender_fpr,
            recipient_fpr=recipient_fpr,
            package_id=package_id,
            kem_ct=kem_ct,
            chunk_size=chunk_size,
            flags=flags,
        )


# ---- Key derivation ------------------------------------------------------


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = suite.AEAD_KEY_LEN) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def derive_master(shared_secret: bytes, header_digest: bytes) -> bytes:
    if len(shared_secret) != suite.KEM_SS_LEN:
        raise FormatError("shared secret has the wrong length")
    if len(header_digest) != 32:
        raise FormatError("header digest has the wrong length")
    return _hkdf(shared_secret, header_digest, suite.INFO_MASTER)


def derive_chunk_key(master: bytes, header_digest: bytes, index: int) -> bytes:
    if not 0 <= index < suite.MAX_CHUNKS:
        raise LimitError(f"chunk index {index} out of range")
    return _hkdf(master, header_digest, suite.INFO_CHUNK + u64(index))


def derive_completion_key(master: bytes, header_digest: bytes) -> bytes:
    return _hkdf(master, header_digest, suite.INFO_COMPLETE)


def chunk_aad(header_digest: bytes, index: int, pt_len: int, final: bool) -> bytes:
    return b"".join(
        [
            suite.AAD_CHUNK_PREFIX,
            header_digest,
            u64(index),
            u32(pt_len),
            u8(1 if final else 0),
        ]
    )


def completion_aad(header_digest: bytes, total_bytes: int, chunk_count: int) -> bytes:
    return b"".join(
        [suite.AAD_COMPLETE_PREFIX, header_digest, u64(total_bytes), u64(chunk_count)]
    )


def signature_message(body_sha512: bytes) -> bytes:
    if len(body_sha512) != 64:
        raise FormatError("body digest must be SHA-512")
    return suite.SIG_CONTEXT + body_sha512


# ---- Results -------------------------------------------------------------


@dataclass(frozen=True)
class SealResult:
    package_path: Path
    package_id: bytes
    total_bytes: int
    chunk_count: int
    recipient_fingerprint: str

    @property
    def package_id_hex(self) -> str:
        return self.package_id.hex()


@dataclass(frozen=True)
class OpenResult:
    output_path: Path
    package_id: bytes
    total_bytes: int
    chunk_count: int
    sender_name: str
    sender_fingerprint: str

    @property
    def package_id_hex(self) -> str:
        return self.package_id.hex()


class _HashingWriter:
    """Writes through to a stream while hashing every byte for the signature."""

    __slots__ = ("_out", "_hash", "_written")

    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self._hash = hashlib.sha512()
        self._written = 0

    def write(self, data: bytes) -> None:
        self._out.write(data)
        self._hash.update(data)
        self._written = checked_add(
            self._written, len(data), what="serialized package length"
        )

    @property
    def digest(self) -> bytes:
        return self._hash.digest()

    @property
    def written(self) -> int:
        return self._written


# ---- Sealing -------------------------------------------------------------


def seal_file(
    *,
    sender: Identity,
    recipient: Contact,
    input_path: Path | str,
    output_path: Path | str,
    overwrite: bool = False,
    progress: Optional[ProgressHook] = None,
) -> SealResult:
    """Encrypt and sign `input_path` into an ALBPKG/1 package.

    The recipient must be a `verified` contact. Bare public identities are
    rejected by both the API and CLI.
    """
    suite.check_provider()

    if isinstance(recipient, Contact):
        recipient.require_usable()
        recipient_public = recipient.public
    else:
        raise TrustError("a verified Contact is required; bare public keys are not trusted")

    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.is_file():
        raise IOErrorAlbpkg(f"input is not a regular file: {input_path}")
    plaintext_size = input_path.stat().st_size
    if plaintext_size > suite.MAX_PLAINTEXT:
        raise LimitError(
            f"input is {plaintext_size} bytes; the maximum is "
            f"{suite.MAX_PLAINTEXT} bytes (1 TiB)"
        )

    shared_secret, kem_ct = recipient_public.kem_key().encapsulate()
    secret_buf = bytearray(shared_secret)
    master_buf: Optional[bytearray] = None

    try:
        header = Header(
            sender_fpr=sender.fingerprint,
            recipient_fpr=recipient_public.fingerprint,
            package_id=secrets.token_bytes(suite.PACKAGE_ID_LEN),
            kem_ct=kem_ct,
        )
        header_bytes = header.serialize()
        header_digest = hashlib.sha256(header_bytes).digest()
        master_buf = bytearray(derive_master(bytes(secret_buf), header_digest))

        total_bytes = 0
        chunk_count = 0

        with open(input_path, "rb") as src, atomic_output(
            output_path, overwrite=overwrite
        ) as raw_out:
            out = _HashingWriter(raw_out)
            out.write(header_bytes)

            # One-chunk look-ahead so the final marker is known before the
            # chunk it belongs to is emitted, without seeking the input.
            pending = read_at_most(src, suite.CHUNK_SIZE)
            while True:
                lookahead = read_at_most(src, suite.CHUNK_SIZE)
                final = len(lookahead) == 0
                if len(pending) != suite.CHUNK_SIZE and not final:
                    raise IOErrorAlbpkg("short read from input before end of file")

                _emit_chunk(
                    out, master_buf, header_digest, chunk_count, pending, final
                )
                total_bytes = checked_add(
                    total_bytes,
                    len(pending),
                    limit=suite.MAX_PLAINTEXT,
                    what="plaintext",
                )
                chunk_count = checked_add(
                    chunk_count, 1, limit=suite.MAX_CHUNKS, what="chunk count"
                )
                if progress:
                    progress(total_bytes, chunk_count)
                if final:
                    break
                pending = lookahead

            # Completion record.
            done_key = bytearray(derive_completion_key(bytes(master_buf), header_digest))
            try:
                completion_pt = u64(total_bytes) + u64(chunk_count)
                completion_ct = AESGCM(bytes(done_key)).encrypt(
                    suite.AEAD_NONCE,
                    completion_pt,
                    completion_aad(header_digest, total_bytes, chunk_count),
                )
            finally:
                wipe(done_key)
            out.write(completion_ct)

            # Signature over every byte emitted so far.
            sig = sender.sig_private.sign(signature_message(out.digest))
            if len(sig) != suite.SIG_LEN:
                raise FormatError("unexpected ML-DSA-65 signature length")
            raw_out.write(sig)
            raw_out.write(u32(len(sig)))
            raw_out.write(suite.SIG_TRAILER_MAGIC)

        return SealResult(
            package_path=output_path,
            package_id=header.package_id,
            total_bytes=total_bytes,
            chunk_count=chunk_count,
            recipient_fingerprint=format_fingerprint(recipient_public.fingerprint),
        )
    finally:
        wipe(secret_buf)
        if master_buf is not None:
            wipe(master_buf)


def _emit_chunk(
    out: _HashingWriter,
    master: bytearray,
    header_digest: bytes,
    index: int,
    plaintext: bytes,
    final: bool,
) -> None:
    key = bytearray(derive_chunk_key(bytes(master), header_digest, index))
    try:
        ct = AESGCM(bytes(key)).encrypt(
            suite.AEAD_NONCE,
            plaintext,
            chunk_aad(header_digest, index, len(plaintext), final),
        )
    finally:
        wipe(key)
    out.write(u8(1 if final else 0))
    out.write(u32(len(plaintext)))
    out.write(ct)


def read_at_most(stream: BinaryIO, n: int) -> bytes:
    """Read up to `n` bytes, looping over short reads."""
    parts: list[bytes] = []
    remaining = n
    while remaining:
        piece = stream.read(remaining)
        if not piece:
            break
        parts.append(piece)
        remaining -= len(piece)
    if len(parts) == 1:
        return parts[0]
    return b"".join(parts)


# ---- Opening -------------------------------------------------------------


def open_file(
    *,
    recipient: Identity,
    contacts: ContactStore,
    package_path: Path | str,
    output_path: Path | str,
    overwrite: bool = False,
    progress: Optional[ProgressHook] = None,
) -> OpenResult:
    """Verify and decrypt an ALBPKG/1 package.

    The signature is verified against the trusted sender before any plaintext is
    produced, and the result is published only after the final completion record
    has verified.
    """
    suite.check_provider()
    package_path = Path(package_path)
    output_path = Path(output_path)

    if not package_path.is_file():
        raise IOErrorAlbpkg(f"package is not a regular file: {package_path}")

    with open(package_path, "rb") as stream:
        return open_stream(recipient=recipient, contacts=contacts, stream=stream,
                           output_path=output_path, overwrite=overwrite, progress=progress)



def open_stream(
    *,
    recipient: Identity,
    contacts: ContactStore,
    stream: BinaryIO,
    output_path: Path | str,
    overwrite: bool = False,
    progress: Optional[ProgressHook] = None,
) -> OpenResult:
    """Open a package from an arbitrary stream.

    A non-seekable stream is spooled, bounded by the maximum package size, into
    a private temporary file first, because the signature at the tail must be
    verified before any decryption begins.
    """
    suite.check_provider()
    output_path = Path(output_path)

    # Snapshot even seekable input: do not decrypt bytes different from those signed.
    with private_spool(output_path.parent) as (spool, spool_path):
        copied = 0
        while True:
            block = stream.read(1 << 20)
            if not block:
                break
            copied = checked_add(
                copied,
                len(block),
                limit=suite.MAX_PACKAGE_SIZE,
                what="spooled package size",
            )
            spool.write(block)
        spool.flush()
        os.fsync(spool.fileno())
        with open(spool_path, "rb") as reread:
            return _open_seekable(
                stream=reread,
                size=copied,
                recipient=recipient,
                contacts=contacts,
                output_path=output_path,
                overwrite=overwrite,
                progress=progress,
            )


MIN_PACKAGE_SIZE = (
    suite.HEADER_LEN
    + suite.CHUNK_FRAME_OVERHEAD  # one empty final chunk
    + suite.COMPLETION_LEN
    + suite.SIG_LEN
    + suite.SIG_TRAILER_LEN
)


def _open_seekable(
    *,
    stream: BinaryIO,
    size: int,
    recipient: Identity,
    contacts: ContactStore,
    output_path: Path,
    overwrite: bool,
    progress: Optional[ProgressHook],
) -> OpenResult:
    base = stream.tell()

    if size < MIN_PACKAGE_SIZE:
        raise FormatError(f"package is too small to be valid ({size} bytes)")
    if size > suite.MAX_PACKAGE_SIZE:
        raise LimitError(f"package is larger than the format permits ({size} bytes)")

    # -- 1. header --
    header_bytes = read_exact(stream, suite.HEADER_LEN, "package header")
    header = Header.parse(header_bytes)
    header_digest = hashlib.sha256(header_bytes).digest()

    # -- 2. trust --
    if not fingerprints_equal(header.recipient_fpr, recipient.fingerprint):
        raise TrustError(
            "this package is addressed to a different recipient "
            f"({format_fingerprint(header.recipient_fpr)})"
        )
    sender = contacts.require(header.sender_fpr)
    sender.require_usable()

    # -- 3. signature, before any decryption --
    trailer_offset = base + size - suite.SIG_TRAILER_LEN
    stream.seek(trailer_offset)
    trailer = read_exact(stream, suite.SIG_TRAILER_LEN, "signature trailer")
    sig_len = int.from_bytes(trailer[:4], "big")
    if trailer[4:] != suite.SIG_TRAILER_MAGIC:
        raise FormatError("missing signature trailer; the package is truncated or padded")
    if sig_len != suite.SIG_LEN:
        raise FormatError(f"noncanonical signature length {sig_len}")

    body_len = size - suite.SIG_TRAILER_LEN - sig_len
    if body_len < suite.HEADER_LEN:
        raise FormatError("signature block overlaps the package body")

    stream.seek(base + body_len)
    signature = read_exact(stream, sig_len, "signature")

    stream.seek(base)
    body_hash = hashlib.sha512()
    remaining = body_len
    while remaining:
        block = read_at_most(stream, min(1 << 20, remaining))
        if not block:
            raise FormatError("package body is shorter than its framing declares")
        body_hash.update(block)
        remaining -= len(block)

    try:
        sender.public.sig_key().verify(signature, signature_message(body_hash.digest()))
    except InvalidSignature as exc:
        raise AuthError(
            f"signature does not verify against contact '{sender.name}'"
        ) from exc

    # -- 4. decrypt --
    try:
        shared_secret = recipient.kem_private.decapsulate(header.kem_ct)
    except Exception as exc:
        raise AuthError("ML-KEM decapsulation failed for this encapsulation") from exc
    secret_buf = bytearray(shared_secret)
    master_buf: Optional[bytearray] = None

    try:
        master_buf = bytearray(derive_master(bytes(secret_buf), header_digest))

        stream.seek(base + suite.HEADER_LEN)
        cursor = suite.HEADER_LEN
        body_end = body_len - suite.COMPLETION_LEN
        if body_end < cursor:
            raise FormatError("package has no room for a completion record")

        total_bytes = 0
        chunk_count = 0
        saw_final = False

        with atomic_output(output_path, overwrite=overwrite) as dest:
            while cursor < body_end:
                if chunk_count >= suite.MAX_CHUNKS:
                    raise LimitError("package exceeds the maximum chunk count")
                if saw_final:
                    raise FormatError("chunk records continue past the final chunk")

                frame = read_exact(stream, 5, "chunk framing")
                final_flag = frame[0]
                if final_flag not in (0, 1):
                    raise FormatError(f"noncanonical final marker {final_flag}")
                pt_len = int.from_bytes(frame[1:5], "big")

                if pt_len > header.chunk_size:
                    raise LimitError(
                        f"chunk {chunk_count} declares {pt_len} bytes, "
                        f"over the {header.chunk_size}-byte chunk size"
                    )
                final = final_flag == 1
                if not final and pt_len != header.chunk_size:
                    raise FormatError(
                        f"chunk {chunk_count} is short but is not marked final"
                    )
                if pt_len == 0 and not (final and chunk_count == 0):
                    raise FormatError("only a lone final chunk may be empty")

                ct_len = checked_add(pt_len, suite.AEAD_TAG_LEN, what="chunk record")
                cursor = checked_add(cursor, 5 + ct_len, what="package offset")
                if cursor > body_end:
                    raise FormatError(
                        f"chunk {chunk_count} runs past the completion record"
                    )

                ct = read_exact(stream, ct_len, f"chunk {chunk_count}")
                key = bytearray(
                    derive_chunk_key(bytes(master_buf), header_digest, chunk_count)
                )
                try:
                    plaintext = AESGCM(bytes(key)).decrypt(
                        suite.AEAD_NONCE,
                        ct,
                        chunk_aad(header_digest, chunk_count, pt_len, final),
                    )
                except InvalidTag as exc:
                    raise AuthError(
                        f"authentication failed on chunk {chunk_count}"
                    ) from exc
                finally:
                    wipe(key)

                if len(plaintext) != pt_len:
                    raise FormatError(f"chunk {chunk_count} plaintext length mismatch")

                dest.write(plaintext)
                total_bytes = checked_add(
                    total_bytes, pt_len, limit=suite.MAX_PLAINTEXT, what="plaintext"
                )
                chunk_count += 1
                saw_final = final
                if progress:
                    progress(total_bytes, chunk_count)

            if not saw_final:
                raise FormatError("package has no final chunk; it is truncated")
            if cursor != body_end:
                raise FormatError("chunk records do not end at the completion record")

            # -- 5. completion --
            completion_ct = read_exact(
                stream, suite.COMPLETION_LEN, "completion record"
            )
            done_key = bytearray(
                derive_completion_key(bytes(master_buf), header_digest)
            )
            try:
                completion_pt = AESGCM(bytes(done_key)).decrypt(
                    suite.AEAD_NONCE,
                    completion_ct,
                    completion_aad(header_digest, total_bytes, chunk_count),
                )
            except InvalidTag as exc:
                raise AuthError(
                    "completion record does not match the decrypted contents; "
                    "the package is truncated or altered"
                ) from exc
            finally:
                wipe(done_key)

            if completion_pt != u64(total_bytes) + u64(chunk_count):
                raise AuthError("completion record contents disagree with the package")

        return OpenResult(
            output_path=output_path,
            package_id=header.package_id,
            total_bytes=total_bytes,
            chunk_count=chunk_count,
            sender_name=sender.name,
            sender_fingerprint=format_fingerprint(sender.fingerprint),
        )
    finally:
        wipe(secret_buf)
        if master_buf is not None:
            wipe(master_buf)


__all__ = [
    "Header",
    "OpenResult",
    "SealResult",
    "chunk_aad",
    "completion_aad",
    "derive_chunk_key",
    "derive_completion_key",
    "derive_master",
    "open_file",
    "open_stream",
    "seal_file",
    "signature_message",
]
