"""Regressions for security boundaries introduced during consolidation."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from albpkg.contacts import Contact, ContactStore, Trust
from albpkg.errors import TrustError, LimitError
from albpkg.fsutil import atomic_output
from albpkg.identity import generate_identity, load_identity
from albpkg.package import open_file, seal_file


def test_late_destination_is_preserved(tmp_path):
    destination = tmp_path / "destination"
    with pytest.raises(FileExistsError):
        with atomic_output(destination) as output:
            output.write(b"new output")
            destination.write_bytes(b"other writer")
    assert destination.read_bytes() == b"other writer"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["destination"]


def test_bare_recipient_is_rejected(tmp_path):
    sender, recipient = generate_identity(), generate_identity()
    source, output = tmp_path / "source", tmp_path / "output"
    source.write_bytes(b"test")
    with pytest.raises(TrustError):
        seal_file(sender=sender, recipient=recipient.public, input_path=source, output_path=output)
    assert not output.exists()


def test_identity_input_is_bounded_before_passphrase(tmp_path):
    source = tmp_path / "oversized"
    source.write_bytes(b"x" * 65537)
    def unexpected_prompt(_):
        pytest.fail("oversized identity requested a passphrase")
    with pytest.raises(LimitError):
        load_identity(source, passphrase_provider=unexpected_prompt)


def test_open_uses_snapshot_when_original_changes(tmp_path):
    sender, recipient = generate_identity(), generate_identity()
    source, package, output = (tmp_path / name for name in ("source", "package", "output"))
    data = b"a" * ((1 << 20) + 1)
    source.write_bytes(data)
    seal_file(sender=sender, recipient=Contact("recipient", recipient.public, Trust.VERIFIED), input_path=source, output_path=package)
    contacts = ContactStore(tmp_path / "contacts")
    contacts.import_contact("sender", sender.public)
    contacts.verify_contact("sender", sender.fingerprint.hex())
    def replace_original(*_args):
        package.write_bytes(b"concurrently replaced input")
    open_file(recipient=recipient, contacts=contacts, package_path=package, output_path=output, progress=replace_original)
    assert output.read_bytes() == data
