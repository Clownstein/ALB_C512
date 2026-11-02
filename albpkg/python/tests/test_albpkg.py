"""Acceptance tests for the ALBPKG/1 Python reference implementation.

These map onto the release gates: round-trip including empty files and chunk
boundaries, and explicit rejection of wrong recipients, untrusted or revoked
senders, altered headers, substituted encapsulations, bad signatures and tags,
reordered or duplicated chunks, truncation, appended data, and overflow.

Run:  python -m pytest albpkg/python/tests -q
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import albpkg  # noqa: E402
from albpkg import suite  # noqa: E402
from albpkg.contacts import Contact, ContactStore, Trust  # noqa: E402
from albpkg.errors import (  # noqa: E402
    AuthError,
    FormatError,
    IOErrorAlbpkg,
    LimitError,
    PassphraseError,
    TrustError,
    UnsupportedError,
)
from albpkg.identity import (  # noqa: E402
    PublicIdentity,
    format_fingerprint,
    generate_identity,
    load_identity,
    parse_fingerprint,
    save_identity,
)
from albpkg.package import (  # noqa: E402
    Header,
    open_file,
    open_stream,
    seal_file,
)
from albpkg.wire import ByteReader, checked_add, checked_mul, u32  # noqa: E402

PASSPHRASE = "correct horse battery staple"


def pp(_prompt: str) -> str:
    return PASSPHRASE


# ---- Fixtures ------------------------------------------------------------


@pytest.fixture(scope="module")
def alice():
    return generate_identity()


@pytest.fixture(scope="module")
def bob():
    return generate_identity()


@pytest.fixture(scope="module")
def mallory():
    return generate_identity()


@pytest.fixture
def store(tmp_path):
    return ContactStore(tmp_path / "contacts")


@pytest.fixture
def bob_trusts_alice(store, alice):
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())
    return store


def seal(tmp_path, sender, recipient_public, data: bytes, name="pkg.albpkg") -> Path:
    src = tmp_path / f"{name}.in"
    src.write_bytes(data)
    out = tmp_path / name
    seal_file(
        sender=sender,
        recipient=Contact("fixture", recipient_public, Trust.VERIFIED),
        input_path=src,
        output_path=out,
        overwrite=True,
    )
    return out


def open_pkg(pkg: Path, recipient, store, out: Path):
    return open_file(
        recipient=recipient,
        contacts=store,
        package_path=pkg,
        output_path=out,
        overwrite=True,
    )


# ---- Identity and fingerprints ------------------------------------------


def test_identity_keys_are_independent(alice):
    assert alice.kem_private.public_key().public_bytes_raw() != (
        alice.sig_private.public_key().public_bytes_raw()
    )
    assert len(alice.public.pubid) == suite.PUBID_LEN == 3150


def test_fingerprint_covers_both_keys(alice, bob):
    swapped = PublicIdentity(alice.public.kem_public_bytes, bob.public.sig_public_bytes)
    assert swapped.fingerprint != alice.public.fingerprint
    assert swapped.fingerprint != bob.public.fingerprint


def test_fingerprint_formatting_round_trip(alice):
    text = alice.public.fingerprint_text
    assert len(text) == 64 + 7
    assert parse_fingerprint(text) == alice.public.fingerprint
    assert parse_fingerprint(alice.public.fingerprint.hex()) == alice.public.fingerprint


@pytest.mark.parametrize("bad", ["", "abcd", "1a2b3c4d", "z" * 64, "ab" * 33])
def test_truncated_or_invalid_fingerprints_rejected(bad):
    with pytest.raises(FormatError):
        parse_fingerprint(bad)


def test_armored_round_trip(alice):
    restored = PublicIdentity.from_armored(alice.public.to_armored())
    assert restored.fingerprint == alice.public.fingerprint


def test_armored_fingerprint_header_must_match(alice, bob):
    armored = alice.public.to_armored().replace(
        alice.public.fingerprint.hex(), bob.public.fingerprint.hex()
    )
    with pytest.raises(FormatError):
        PublicIdentity.from_armored(armored)


def test_armored_body_corruption_rejected(alice):
    armored = alice.public.to_armored()
    lines = armored.split("\n")
    lines[3] = ("A" if lines[3][0] != "A" else "B") + lines[3][1:]
    with pytest.raises(FormatError):
        PublicIdentity.from_armored("\n".join(lines))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:-1],
        lambda b: b + b"\x00",
        lambda b: b"XXXXXXXX" + b[8:],
        lambda b: b[:8] + b"\x00\x02" + b[10:],  # wrong suite id
        lambda b: b[:10] + b"\x00\x10" + b[12:],  # wrong kem length
    ],
)
def test_noncanonical_pubid_rejected(alice, mutate):
    with pytest.raises((FormatError, UnsupportedError)):
        PublicIdentity.from_pubid(mutate(alice.public.pubid))


# ---- Private identity storage -------------------------------------------


def test_identity_file_round_trip_and_permissions(tmp_path, alice):
    path = tmp_path / "id.key"
    save_identity(alice, path, passphrase_provider=pp)
    from albpkg.fsutil import permissions_are_owner_only

    assert permissions_are_owner_only(path)
    loaded = load_identity(path, passphrase_provider=pp)
    assert loaded.fingerprint == alice.fingerprint


def test_identity_file_wrong_passphrase(tmp_path, alice):
    path = tmp_path / "id.key"
    save_identity(alice, path, passphrase_provider=pp)
    with pytest.raises(PassphraseError):
        load_identity(path, passphrase_provider=lambda _p: "wrong passphrase")


def test_short_passphrase_rejected(tmp_path, alice):
    with pytest.raises(PassphraseError):
        save_identity(alice, tmp_path / "id.key", passphrase_provider=lambda _p: "short")


def test_identity_file_truncation_rejected(tmp_path, alice):
    path = tmp_path / "id.key"
    save_identity(alice, path, passphrase_provider=pp)
    blob = path.read_bytes()
    path.write_bytes(blob[:-5])
    with pytest.raises(FormatError):
        load_identity(path, passphrase_provider=pp)


def test_identity_file_trailing_bytes_rejected(tmp_path, alice):
    path = tmp_path / "id.key"
    save_identity(alice, path, passphrase_provider=pp)
    path.write_bytes(path.read_bytes() + b"\x00")
    with pytest.raises(FormatError):
        load_identity(path, passphrase_provider=pp)


def test_save_identity_does_not_clobber_without_overwrite(tmp_path, alice, bob):
    path = tmp_path / "id.key"
    save_identity(alice, path, passphrase_provider=pp)
    original = path.read_bytes()
    with pytest.raises(IOErrorAlbpkg):
        save_identity(bob, path, passphrase_provider=pp)
    assert path.read_bytes() == original


# ---- Contact trust -------------------------------------------------------


def test_import_is_unverified_and_unusable(store, alice):
    contact = store.import_contact("alice", alice.public)
    assert contact.trust is Trust.UNVERIFIED
    with pytest.raises(TrustError):
        contact.require_usable()


def test_verify_requires_exact_fingerprint(store, alice, bob):
    store.import_contact("alice", alice.public)
    with pytest.raises(TrustError):
        store.verify_contact("alice", bob.public.fingerprint.hex())
    assert store.by_name("alice").trust is Trust.UNVERIFIED
    store.verify_contact("alice", alice.public.fingerprint_text)
    assert store.by_name("alice").trust is Trust.VERIFIED


def test_key_replacement_resets_trust(store, alice, bob):
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())
    store.import_contact("alice", bob.public)  # same name, different key
    for contact in store.list():
        assert contact.trust is Trust.UNVERIFIED
    with pytest.raises(TrustError):
        store.by_name("alice")  # ambiguous: two keys under one name


def test_failed_replacement_demotes_old_fingerprint_first(store, alice, bob, monkeypatch):
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())
    write = store._write

    def fail_new_contact(contact):
        if contact.fingerprint == bob.public.fingerprint:
            raise OSError("injected publication failure")
        write(contact)

    monkeypatch.setattr(store, "_write", fail_new_contact)
    with pytest.raises(OSError):
        store.import_contact("alice", bob.public)
    assert store.require(alice.public.fingerprint).trust is Trust.UNVERIFIED


def test_reimport_same_key_preserves_trust(store, alice):
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())
    again = store.import_contact("alice", alice.public)
    assert again.trust is Trust.VERIFIED


def test_revoked_contact_rejected(store, alice):
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())
    store.revoke("alice")
    with pytest.raises(TrustError):
        store.by_name("alice").require_usable()


def test_contact_file_tampering_rejected(store, alice):
    store.import_contact("alice", alice.public)
    path = next(store.directory.glob("*.contact"))
    path.write_text(path.read_text().replace('"unverified"', '"nonsense"'))
    with pytest.raises(FormatError):
        store.list()


def test_contact_file_renamed_to_wrong_fingerprint_rejected(store, alice, bob):
    store.import_contact("alice", alice.public)
    path = next(store.directory.glob("*.contact"))
    path.rename(store.directory / f"{bob.public.fingerprint.hex()}.contact")
    with pytest.raises(FormatError):
        store.list()


# ---- Round trip ----------------------------------------------------------

CHUNK = suite.CHUNK_SIZE

ROUND_TRIP_SIZES = [
    0,
    1,
    1024,
    CHUNK - 1,
    CHUNK,
    CHUNK + 1,
    2 * CHUNK,
    2 * CHUNK + 7,
]


@pytest.mark.parametrize("size", ROUND_TRIP_SIZES)
def test_round_trip(tmp_path, alice, bob, bob_trusts_alice, size):
    data = os.urandom(size)
    pkg = seal(tmp_path, alice, bob.public, data)
    out = tmp_path / "out.bin"
    result = open_pkg(pkg, bob, bob_trusts_alice, out)
    assert out.read_bytes() == data
    assert result.total_bytes == size
    assert result.sender_name == "alice"
    expected_chunks = max(1, (size + CHUNK - 1) // CHUNK)
    assert result.chunk_count == expected_chunks


def test_empty_file_produces_one_final_chunk(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"")
    out = tmp_path / "out.bin"
    result = open_pkg(pkg, bob, bob_trusts_alice, out)
    assert result.chunk_count == 1
    assert result.total_bytes == 0
    assert out.read_bytes() == b""


def test_package_ids_and_ciphertexts_are_fresh(tmp_path, alice, bob):
    data = b"same plaintext every time"
    a = seal(tmp_path, alice, bob.public, data, "a.albpkg")
    b = seal(tmp_path, alice, bob.public, data, "b.albpkg")
    assert a.read_bytes() != b.read_bytes()
    ha = Header.parse(a.read_bytes()[: suite.HEADER_LEN])
    hb = Header.parse(b.read_bytes()[: suite.HEADER_LEN])
    assert ha.package_id != hb.package_id
    assert ha.kem_ct != hb.kem_ct


def test_non_seekable_input_is_spooled(tmp_path, alice, bob, bob_trusts_alice):
    data = os.urandom(5000)
    pkg = seal(tmp_path, alice, bob.public, data)

    class Pipe(io.RawIOBase):
        def __init__(self, blob):
            self._buf = io.BytesIO(blob)

        def readable(self):
            return True

        def seekable(self):
            return False

        def read(self, n=-1):
            return self._buf.read(n)

        def readinto(self, b):
            return self._buf.readinto(b)

    out = tmp_path / "out.bin"
    result = open_stream(
        recipient=bob,
        contacts=bob_trusts_alice,
        stream=Pipe(pkg.read_bytes()),
        output_path=out,
        overwrite=True,
    )
    assert result.total_bytes == len(data)
    assert out.read_bytes() == data


# ---- Trust enforcement on open ------------------------------------------


def test_wrong_recipient_rejected(tmp_path, alice, bob, mallory, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"for bob only")
    with pytest.raises(TrustError):
        open_pkg(pkg, mallory, bob_trusts_alice, tmp_path / "out.bin")


def test_unknown_sender_rejected(tmp_path, alice, bob, store):
    pkg = seal(tmp_path, alice, bob.public, b"hello")
    with pytest.raises(TrustError):
        open_pkg(pkg, bob, store, tmp_path / "out.bin")


def test_unverified_sender_rejected(tmp_path, alice, bob, store):
    store.import_contact("alice", alice.public)
    pkg = seal(tmp_path, alice, bob.public, b"hello")
    with pytest.raises(TrustError):
        open_pkg(pkg, bob, store, tmp_path / "out.bin")


def test_revoked_sender_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"hello")
    bob_trusts_alice.revoke("alice")
    with pytest.raises(TrustError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_sealing_to_unverified_contact_refused(tmp_path, alice, bob, store):
    contact = store.import_contact("bob", bob.public)
    src = tmp_path / "in.bin"
    src.write_bytes(b"x")
    with pytest.raises(TrustError):
        seal_file(
            sender=alice,
            recipient=contact,
            input_path=src,
            output_path=tmp_path / "out.albpkg",
        )
    assert not (tmp_path / "out.albpkg").exists()


def test_sealing_to_revoked_contact_refused(tmp_path, alice, bob, store):
    store.import_contact("bob", bob.public)
    store.verify_contact("bob", bob.public.fingerprint.hex())
    contact = store.revoke("bob")
    src = tmp_path / "in.bin"
    src.write_bytes(b"x")
    with pytest.raises(TrustError):
        seal_file(
            sender=alice,
            recipient=contact,
            input_path=src,
            output_path=tmp_path / "out.albpkg",
        )


# ---- Tamper matrix -------------------------------------------------------


def flip(blob: bytes, offset: int) -> bytes:
    out = bytearray(blob)
    out[offset] ^= 0x01
    return bytes(out)


TAMPER_OFFSETS = {
    "magic": 0,
    "format_version": 8,
    "suite_id": 10,
    "header_len": 15,
    "flags": 16,
    "chunk_size": 23,
    "sender_fpr": 24,
    "recipient_fpr": 56,
    "package_id": 88,
    "kem_ct_len": 105,
    "kem_ct": 110,
}


@pytest.mark.parametrize("field,offset", sorted(TAMPER_OFFSETS.items()))
def test_header_tampering_rejected(
    tmp_path, alice, bob, bob_trusts_alice, field, offset
):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    pkg.write_bytes(flip(pkg.read_bytes(), offset))
    out = tmp_path / "out.bin"
    with pytest.raises((AuthError, FormatError, TrustError, UnsupportedError, LimitError)):
        open_pkg(pkg, bob, bob_trusts_alice, out)
    assert not out.exists()


def test_substituted_encapsulation_rejected(tmp_path, alice, bob, mallory, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(2048))
    blob = bytearray(pkg.read_bytes())
    _, other_ct = mallory.public.kem_key().encapsulate()
    start = 8 + 2 + 2 + 4 + 4 + 4 + 32 + 32 + 16 + 2
    blob[start : start + suite.KEM_CT_LEN] = other_ct
    pkg.write_bytes(bytes(blob))
    with pytest.raises((AuthError, FormatError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_bad_signature_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(2048))
    blob = bytearray(pkg.read_bytes())
    sig_start = len(blob) - suite.SIG_TRAILER_LEN - suite.SIG_LEN
    blob[sig_start + 10] ^= 0xFF
    pkg.write_bytes(bytes(blob))
    with pytest.raises(AuthError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_signature_from_other_sender_rejected(tmp_path, alice, bob, mallory, store):
    """Mallory re-signs Alice's package body; Bob trusts only Alice."""
    store.import_contact("alice", alice.public)
    store.verify_contact("alice", alice.public.fingerprint.hex())

    pkg = seal(tmp_path, alice, bob.public, os.urandom(1024))
    blob = bytearray(pkg.read_bytes())
    body_len = len(blob) - suite.SIG_TRAILER_LEN - suite.SIG_LEN

    import hashlib

    from albpkg.package import signature_message

    body = bytes(blob[:body_len])
    forged = mallory.sig_private.sign(signature_message(hashlib.sha512(body).digest()))
    blob[body_len : body_len + suite.SIG_LEN] = forged
    pkg.write_bytes(bytes(blob))

    with pytest.raises(AuthError):
        open_pkg(pkg, bob, store, tmp_path / "out.bin")


def test_ciphertext_tampering_rejected(tmp_path, alice, bob, bob_trusts_alice):
    """A flipped ciphertext bit fails the signature first, then the tag."""
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    blob = bytearray(pkg.read_bytes())
    blob[suite.HEADER_LEN + 20] ^= 0x01
    pkg.write_bytes(bytes(blob))
    out = tmp_path / "out.bin"
    with pytest.raises(AuthError):
        open_pkg(pkg, bob, bob_trusts_alice, out)
    assert not out.exists()


def test_chunk_reordering_rejected(tmp_path, alice, bob, bob_trusts_alice):
    """Swap two full chunk records and re-sign, so only the AEAD binding remains."""
    data = os.urandom(3 * CHUNK)
    pkg = seal(tmp_path, alice, bob.public, data)
    blob = bytearray(pkg.read_bytes())

    rec = 5 + CHUNK + suite.AEAD_TAG_LEN
    a0 = suite.HEADER_LEN
    a1 = a0 + rec
    a2 = a1 + rec
    blob[a0:a2] = blob[a1:a2] + blob[a0:a1]
    pkg.write_bytes(_resign(bytes(blob), alice))

    with pytest.raises(AuthError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_chunk_duplication_rejected(tmp_path, alice, bob, bob_trusts_alice):
    data = os.urandom(2 * CHUNK)
    pkg = seal(tmp_path, alice, bob.public, data)
    blob = bytearray(pkg.read_bytes())

    rec = 5 + CHUNK + suite.AEAD_TAG_LEN
    a0 = suite.HEADER_LEN
    blob[a0 + rec : a0 + 2 * rec] = blob[a0 : a0 + rec]
    pkg.write_bytes(_resign(bytes(blob), alice))

    with pytest.raises((AuthError, FormatError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_chunk_truncation_rejected(tmp_path, alice, bob, bob_trusts_alice):
    """Drop the last chunk entirely and re-sign: completion record must catch it."""
    data = os.urandom(2 * CHUNK)
    pkg = seal(tmp_path, alice, bob.public, data)
    blob = bytearray(pkg.read_bytes())

    rec = 5 + CHUNK + suite.AEAD_TAG_LEN
    body_len = len(blob) - suite.SIG_TRAILER_LEN - suite.SIG_LEN
    completion = bytes(blob[body_len - suite.COMPLETION_LEN : body_len])
    kept = bytes(blob[: suite.HEADER_LEN + rec]) + completion
    pkg.write_bytes(_resign(kept, alice))

    with pytest.raises((AuthError, FormatError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_byte_truncation_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    blob = pkg.read_bytes()
    pkg.write_bytes(blob[:-1])
    with pytest.raises((FormatError, AuthError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_appended_data_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    pkg.write_bytes(pkg.read_bytes() + b"extra")
    with pytest.raises((FormatError, AuthError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_final_marker_moved_rejected(tmp_path, alice, bob, bob_trusts_alice):
    """Clear the final flag on the last chunk and re-sign."""
    data = os.urandom(1000)
    pkg = seal(tmp_path, alice, bob.public, data)
    blob = bytearray(pkg.read_bytes())
    blob[suite.HEADER_LEN] = 0  # was 1
    pkg.write_bytes(_resign(bytes(blob), alice))
    with pytest.raises((FormatError, AuthError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_oversized_chunk_length_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"small")
    blob = bytearray(pkg.read_bytes())
    blob[suite.HEADER_LEN + 1 : suite.HEADER_LEN + 5] = u32(0xFFFFFFFF)
    pkg.write_bytes(_resign(bytes(blob), alice))
    with pytest.raises((LimitError, FormatError)):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_noncanonical_final_marker_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"small")
    blob = bytearray(pkg.read_bytes())
    blob[suite.HEADER_LEN] = 2
    pkg.write_bytes(_resign(bytes(blob), alice))
    with pytest.raises(FormatError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_completion_record_tampering_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(1024))
    blob = bytearray(pkg.read_bytes())
    body_len = len(blob) - suite.SIG_TRAILER_LEN - suite.SIG_LEN
    blob[body_len - 1] ^= 0x01
    pkg.write_bytes(_resign(bytes(blob), alice))
    with pytest.raises(AuthError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_trailer_magic_required(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"x")
    blob = bytearray(pkg.read_bytes())
    blob[-1] ^= 0xFF
    pkg.write_bytes(bytes(blob))
    with pytest.raises(FormatError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_noncanonical_signature_length_rejected(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"x")
    blob = bytearray(pkg.read_bytes())
    blob[-suite.SIG_TRAILER_LEN : -8] = u32(suite.SIG_LEN + 1)
    pkg.write_bytes(bytes(blob))
    with pytest.raises(FormatError):
        open_pkg(pkg, bob, bob_trusts_alice, tmp_path / "out.bin")


def test_cross_package_splicing_rejected(tmp_path, alice, bob, bob_trusts_alice):
    """Header of one package, body of another."""
    a = seal(tmp_path, alice, bob.public, os.urandom(2048), "a.albpkg")
    b = seal(tmp_path, alice, bob.public, os.urandom(2048), "b.albpkg")
    spliced = a.read_bytes()[: suite.HEADER_LEN] + b.read_bytes()[suite.HEADER_LEN :]
    target = tmp_path / "spliced.albpkg"
    target.write_bytes(_resign(
        spliced[: len(spliced) - suite.SIG_TRAILER_LEN - suite.SIG_LEN], alice
    ))
    with pytest.raises(AuthError):
        open_pkg(target, bob, bob_trusts_alice, tmp_path / "out.bin")


def _resign(body_or_full: bytes, sender) -> bytes:
    """Re-sign a tampered body so a test isolates a non-signature defence."""
    import hashlib

    from albpkg.package import signature_message

    if (
        len(body_or_full) > suite.SIG_TRAILER_LEN
        and body_or_full[-8:] == suite.SIG_TRAILER_MAGIC
    ):
        body = body_or_full[: len(body_or_full) - suite.SIG_TRAILER_LEN - suite.SIG_LEN]
    else:
        body = body_or_full
    sig = sender.sig_private.sign(signature_message(hashlib.sha512(body).digest()))
    return body + sig + u32(len(sig)) + suite.SIG_TRAILER_MAGIC


# ---- Output safety -------------------------------------------------------


def test_destination_preserved_on_failure(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    blob = bytearray(pkg.read_bytes())
    blob[suite.HEADER_LEN + 30] ^= 0x01
    pkg.write_bytes(bytes(blob))

    out = tmp_path / "out.bin"
    out.write_bytes(b"PRECIOUS ORIGINAL")
    with pytest.raises(AuthError):
        open_file(
            recipient=bob,
            contacts=bob_trusts_alice,
            package_path=pkg,
            output_path=out,
            overwrite=True,
        )
    assert out.read_bytes() == b"PRECIOUS ORIGINAL"


def test_no_overwrite_without_flag(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, b"hello")
    out = tmp_path / "out.bin"
    out.write_bytes(b"ORIGINAL")
    with pytest.raises(IOErrorAlbpkg):
        open_file(
            recipient=bob,
            contacts=bob_trusts_alice,
            package_path=pkg,
            output_path=out,
            overwrite=False,
        )
    assert out.read_bytes() == b"ORIGINAL"


def test_no_temporary_files_left_behind(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(4096))
    out = tmp_path / "out.bin"
    open_pkg(pkg, bob, bob_trusts_alice, out)
    leftovers = [p.name for p in tmp_path.iterdir() if ".tmp" in p.name]
    assert leftovers == []


def test_cancellation_publishes_nothing(tmp_path, alice, bob, bob_trusts_alice):
    pkg = seal(tmp_path, alice, bob.public, os.urandom(2 * CHUNK))
    out = tmp_path / "out.bin"

    def cancel(_done, chunks):
        if chunks >= 1:
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        open_file(
            recipient=bob,
            contacts=bob_trusts_alice,
            package_path=pkg,
            output_path=out,
            overwrite=True,
            progress=cancel,
        )
    assert not out.exists()
    assert [p.name for p in tmp_path.iterdir() if ".tmp" in p.name] == []


# ---- Bounds and arithmetic ----------------------------------------------


def test_checked_add_overflow():
    with pytest.raises(LimitError):
        checked_add(2**63, 2**63, limit=2**64 - 1)
    assert checked_add(1, 2) == 3


def test_checked_mul_overflow():
    with pytest.raises(LimitError):
        checked_mul(2**32, 2**32, limit=2**64 - 1)


def test_byte_reader_rejects_trailing_bytes():
    r = ByteReader(b"abcd", "thing")
    r.take(2, "half")
    with pytest.raises(FormatError):
        r.finish()


def test_byte_reader_rejects_overrun():
    r = ByteReader(b"ab", "thing")
    with pytest.raises(FormatError):
        r.take(3, "too much")


def test_max_plaintext_limit_enforced(tmp_path, alice, bob, monkeypatch):
    src = tmp_path / "big.bin"
    src.write_bytes(b"x")
    monkeypatch.setattr(suite, "MAX_PLAINTEXT", 0)
    import albpkg.package as pkgmod

    monkeypatch.setattr(pkgmod.suite, "MAX_PLAINTEXT", 0)
    with pytest.raises(LimitError):
        seal_file(
            sender=alice,
            recipient=Contact("fixture", bob.public, Trust.VERIFIED),
            input_path=src,
            output_path=tmp_path / "out.albpkg",
        )


def test_package_too_small_rejected(tmp_path, bob, store):
    pkg = tmp_path / "tiny.albpkg"
    pkg.write_bytes(b"\x00" * 100)
    with pytest.raises(FormatError):
        open_pkg(pkg, bob, store, tmp_path / "out.bin")


# ---- Key derivation binding ---------------------------------------------


def test_chunk_keys_are_distinct_per_index():
    from albpkg.package import derive_chunk_key

    master = b"\x01" * 32
    hd = b"\x02" * 32
    keys = {derive_chunk_key(master, hd, i) for i in range(64)}
    assert len(keys) == 64


def test_keys_bound_to_header_digest():
    from albpkg.package import derive_master

    ss = b"\x03" * 32
    assert derive_master(ss, b"\x00" * 32) != derive_master(ss, b"\x01" * 32)


def test_completion_key_differs_from_chunk_keys():
    from albpkg.package import derive_chunk_key, derive_completion_key

    master = b"\x04" * 32
    hd = b"\x05" * 32
    done = derive_completion_key(master, hd)
    assert all(done != derive_chunk_key(master, hd, i) for i in range(16))


def test_chunk_index_bounds():
    from albpkg.package import derive_chunk_key

    with pytest.raises(LimitError):
        derive_chunk_key(b"\x00" * 32, b"\x00" * 32, -1)
    with pytest.raises(LimitError):
        derive_chunk_key(b"\x00" * 32, b"\x00" * 32, suite.MAX_CHUNKS)


# ---- No secret leakage ---------------------------------------------------


def test_errors_never_contain_key_material(tmp_path, alice, bob, store):
    pkg = seal(tmp_path, alice, bob.public, b"secret plaintext contents")
    try:
        open_pkg(pkg, bob, store, tmp_path / "out.bin")
    except Exception as exc:  # noqa: BLE001 - this is the assertion
        text = str(exc)
        assert "secret plaintext" not in text
        assert bob.kem_private.private_bytes_raw().hex()[:16] not in text
        assert PASSPHRASE not in text
    else:
        pytest.fail("expected a trust failure")


def test_cli_has_no_passphrase_argument():
    from albpkg.cli import build_parser

    parser = build_parser()
    help_text = parser.format_help()
    assert "--passphrase " not in help_text
    assert "--passphrase-fd" in help_text
    with pytest.raises(SystemExit):
        parser.parse_args(["--passphrase", "hunter2", "show-identity"])


# ---- No C512 in the product path ----------------------------------------


def test_product_does_not_reference_c512():
    root = Path(__file__).resolve().parents[1] / "albpkg"
    for path in root.glob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        assert "c512" not in text.replace("alb_c512", ""), path.name


# ---- CLI end to end ------------------------------------------------------


def test_cli_round_trip(tmp_path, monkeypatch, capsys):
    from albpkg.cli import main

    pass_file = tmp_path / "pass.txt"
    pass_file.write_text(PASSPHRASE, encoding="utf-8")
    monkeypatch.setenv("ALBPKG_PASSPHRASE_FILE", str(pass_file))

    a_home = tmp_path / "alice-home"
    b_home = tmp_path / "bob-home"

    assert main(["--home", str(a_home), "generate-identity"]) == 0
    assert main(["--home", str(b_home), "generate-identity"]) == 0

    a_pub = tmp_path / "alice.pub"
    b_pub = tmp_path / "bob.pub"
    assert main(["--home", str(a_home), "export-public-identity", str(a_pub)]) == 0
    assert main(["--home", str(b_home), "export-public-identity", str(b_pub)]) == 0

    a_fpr = PublicIdentity.from_armored(a_pub.read_text()).fingerprint.hex()
    b_fpr = PublicIdentity.from_armored(b_pub.read_text()).fingerprint.hex()

    assert main(["--home", str(a_home), "import-contact", "bob", str(b_pub)]) == 0
    assert main(["--home", str(b_home), "import-contact", "alice", str(a_pub)]) == 0

    # Sealing to an unverified contact must fail.
    src = tmp_path / "message.txt"
    src.write_bytes(os.urandom(200000))
    pkg = tmp_path / "message.albpkg"
    assert main(
        ["--home", str(a_home), "seal", str(src), str(pkg), "--to", "bob"]
    ) == 2

    assert main(["--home", str(a_home), "verify-contact", "bob", b_fpr]) == 0
    assert main(["--home", str(b_home), "verify-contact", "alice", a_fpr]) == 0

    assert main(
        ["--home", str(a_home), "seal", str(src), str(pkg), "--to", "bob"]
    ) == 0

    out = tmp_path / "recovered.txt"
    assert main(["--home", str(b_home), "open", str(pkg), str(out)]) == 0
    assert out.read_bytes() == src.read_bytes()

    # Revocation blocks it afterwards.
    assert main(["--home", str(b_home), "revoke-contact", "alice"]) == 0
    assert main(
        ["--home", str(b_home), "open", str(pkg), str(out), "--overwrite"]
    ) == 2

    captured = capsys.readouterr()
    assert PASSPHRASE not in captured.out
    assert PASSPHRASE not in captured.err
