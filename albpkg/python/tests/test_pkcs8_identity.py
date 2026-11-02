import base64
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from albpkg.errors import FormatError, LimitError, PassphraseError
from albpkg.identity import (
    _load_legacy_identity,
    _parse_identity_pem,
    _save_legacy_identity,
    generate_identity,
    load_identity,
    migrate_legacy_identity,
    save_identity,
)
from albpkg.pkcs8 import decrypt_private_key_info


PASS = lambda _prompt: "correct horse battery staple"


def test_identity_contains_two_provider_readable_encrypted_pkcs8_objects(tmp_path):
    identity = generate_identity()
    target = tmp_path / "identity.key"
    save_identity(identity, target, passphrase_provider=PASS)
    kem, sig = _parse_identity_pem(target.read_bytes())
    assert type(load_der_private_key(kem, b"correct horse battery staple")).__name__ == "MLKEM768PrivateKey"
    assert type(load_der_private_key(sig, b"correct horse battery staple")).__name__ == "MLDSA65PrivateKey"
    assert load_identity(target, passphrase_provider=PASS).fingerprint == identity.fingerprint


def test_identity_parser_rejects_noncanonical_and_legacy_inputs(tmp_path):
    identity = generate_identity()
    target = tmp_path / "identity.key"
    save_identity(identity, target, passphrase_provider=PASS)
    blob = target.read_bytes()
    for malformed in (
        blob + b"\n",
        blob.replace(b"\n", b"\r\n"),
        blob.replace(b"ALBPKG PRIVATE IDENTITY 1", b"ALBPKG PRIVATE IDENTITY 2"),
    ):
        target.write_bytes(malformed)
        with pytest.raises(FormatError):
            load_identity(target, passphrase_provider=PASS)
    legacy = tmp_path / "legacy.key"
    _save_legacy_identity(identity, legacy, passphrase_provider=PASS)
    with pytest.raises(FormatError):
        load_identity(legacy, passphrase_provider=PASS)


def test_legacy_migration_is_explicit_and_preserves_source(tmp_path):
    identity = generate_identity()
    source, target = tmp_path / "legacy.key", tmp_path / "identity.key"
    _save_legacy_identity(identity, source, passphrase_provider=PASS)
    original = source.read_bytes()
    migrated = migrate_legacy_identity(
        source, target, passphrase_provider=PASS
    )
    assert source.read_bytes() == original
    assert migrated.fingerprint == identity.fingerprint
    assert load_identity(target, passphrase_provider=PASS).fingerprint == identity.fingerprint
    assert _load_legacy_identity(source, passphrase_provider=PASS).fingerprint == identity.fingerprint


def test_pkcs8_profile_rejects_weak_iteration_count_before_kdf(tmp_path):
    identity = generate_identity()
    target = tmp_path / "identity.key"
    save_identity(identity, target, passphrase_provider=PASS)
    kem, _ = _parse_identity_pem(target.read_bytes())
    # The canonical DER integer for 600000 is 02 03 09 27 c0.
    assert b"\x02\x03\x09\x27\xc0" in kem
    weak = kem.replace(b"\x02\x03\x09\x27\xc0", b"\x02\x03\x00\x00\x01", 1)
    with pytest.raises((LimitError, FormatError)):
        decrypt_private_key_info(weak, b"correct horse battery staple")


def test_wrong_passphrase_does_not_reveal_which_key_failed(tmp_path):
    target = tmp_path / "identity.key"
    save_identity(generate_identity(), target, passphrase_provider=PASS)
    with pytest.raises(PassphraseError, match="wrong or the key has been altered"):
        load_identity(target, passphrase_provider=lambda _: "wrong passphrase")
