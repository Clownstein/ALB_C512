"""End-to-end regression for explicit C512 demo migration."""

from __future__ import annotations

import os
from pathlib import Path
import struct
import subprocess
import sys


TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "python"))
sys.path.insert(0, str(PROJECT_ROOT / "albpkg" / "python"))

os.environ["ALB_C512_EXPERIMENTAL"] = "1"

from c512 import encrypt
from albpkg.contacts import ContactStore
from albpkg.fsutil import restrict_permissions
from albpkg.identity import generate_identity, save_identity
from albpkg.package import open_file


def test_explicit_c512_migration(tmp_path: Path) -> None:
    passphrase = "migration test passphrase"
    key = bytes(range(64))
    nonce = bytes(range(32))
    aad = b"legacy research fixture"
    plaintext = bytes(range(256)) * 19
    sealed = encrypt(key, nonce, aad, plaintext)
    legacy = tmp_path / "legacy.c512"
    legacy.write_bytes(
        b"C512"
        + struct.pack("<H", 1)
        + struct.pack("<I", len(plaintext))
        + nonce
        + struct.pack("<I", len(aad))
        + aad
        + sealed
    )
    original = legacy.read_bytes()
    keyfile = tmp_path / "legacy.key"
    keyfile.write_text(key.hex(), encoding="ascii")
    restrict_permissions(keyfile)

    sender = generate_identity()
    recipient = generate_identity()
    task_home = tmp_path / "home"
    task_home.mkdir()
    identity_path = task_home / "identity.key"
    save_identity(
        sender,
        identity_path,
        passphrase_provider=lambda _: passphrase,
    )
    store = ContactStore(task_home / "contacts")
    store.import_contact("recipient", recipient.public)
    store.verify_contact("recipient", recipient.fingerprint.hex())
    recipient_store = ContactStore(tmp_path / "recipient-contacts")
    recipient_store.import_contact("sender", sender.public)
    recipient_store.verify_contact("sender", sender.fingerprint.hex())

    passfile = tmp_path / "passphrase.txt"
    passfile.write_text(passphrase, encoding="utf-8")
    package = tmp_path / "migrated.albpkg"
    env = dict(os.environ)
    env["ALBPKG_PASSPHRASE_FILE"] = str(passfile)
    result = subprocess.run(
        [
            sys.executable,
            str(TOOLS_DIR / "migrate_c512_file.py"),
            str(legacy),
            str(package),
            "--key-file",
            str(keyfile),
            "--home",
            str(task_home),
            "--to",
            "recipient",
            "--experimental",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert legacy.read_bytes() == original
    assert package.is_file()
    assert key.hex() not in result.stdout + result.stderr

    opened = tmp_path / "opened.bin"
    open_file(
        recipient=recipient,
        contacts=recipient_store,
        package_path=package,
        output_path=opened,
    )
    assert opened.read_bytes() == plaintext

    # The production opener never treats a C512 artifact as a package.
    rejected = tmp_path / "rejected.bin"
    try:
        open_file(
            recipient=recipient,
            contacts=recipient_store,
            package_path=legacy,
            output_path=rejected,
        )
    except Exception:
        pass
    else:
        raise AssertionError("production package opener accepted a C512 artifact")
    assert not rejected.exists()
