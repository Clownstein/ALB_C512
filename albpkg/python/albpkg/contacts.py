"""Contact store: import, manual fingerprint verification, revocation.

FORMAT.md section 2.5.  An imported contact starts `unverified` and is useless
until the operator confirms the full 256-bit fingerprint out of band.  Replacing
a name's key resets trust; revocation is permanent until explicitly undone.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional

from .errors import FormatError, IOErrorAlbpkg, TrustError
from .fsutil import atomic_output
from .identity import (
    PublicIdentity,
    fingerprints_equal,
    format_fingerprint,
    parse_fingerprint,
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$")
MAX_CONTACT_FILE = 1 << 16


class Trust(str, Enum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    REVOKED = "revoked"


@dataclass(frozen=True)
class Contact:
    name: str
    public: PublicIdentity
    trust: Trust

    @property
    def fingerprint(self) -> bytes:
        return self.public.fingerprint

    @property
    def fingerprint_text(self) -> str:
        return format_fingerprint(self.fingerprint)

    def require_usable(self) -> None:
        """Raise unless this contact may be sealed to or accepted from."""
        if self.trust is Trust.REVOKED:
            raise TrustError(f"contact '{self.name}' is revoked")
        if self.trust is not Trust.VERIFIED:
            raise TrustError(
                f"contact '{self.name}' is unverified; confirm the full fingerprint "
                f"{self.fingerprint_text} out of band and run 'verify-contact' first"
            )


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise FormatError(
            "contact name must be 1-64 characters of [A-Za-z0-9._@+-] starting "
            "with an alphanumeric"
        )
    return name


class ContactStore:
    """A directory of one JSON file per contact, keyed by fingerprint.

    Files are keyed by fingerprint rather than by name so that a name collision
    can never silently substitute one key for another; the name is an attribute
    inside the record.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    # -- paths --

    def _path_for(self, fpr: bytes) -> Path:
        return self.directory / f"{fpr.hex()}.contact"

    # -- reading --

    def _load_file(self, path: Path) -> Contact:
        try:
            if path.stat().st_size > MAX_CONTACT_FILE:
                raise FormatError(f"contact file {path.name} is implausibly large")
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise IOErrorAlbpkg(f"cannot read contact file {path.name}") from exc
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FormatError(f"contact file {path.name} is not valid JSON") from exc
        if not isinstance(record, dict):
            raise FormatError(f"contact file {path.name} is not an object")

        expected_keys = {"version", "name", "trust", "pubid"}
        if set(record) != expected_keys:
            raise FormatError(f"contact file {path.name} has unexpected fields")
        if record["version"] != 1:
            raise FormatError(f"unsupported contact record version in {path.name}")

        name = validate_name(record["name"])
        try:
            trust = Trust(record["trust"])
        except ValueError as exc:
            raise FormatError(f"unknown trust state in {path.name}") from exc
        try:
            pubid = base64.b64decode(record["pubid"], validate=True)
        except Exception as exc:
            raise FormatError(f"contact file {path.name} has a malformed key") from exc

        public = PublicIdentity.from_pubid(pubid)
        if path.name != f"{public.fingerprint.hex()}.contact":
            raise FormatError(
                f"contact file {path.name} does not match its own key fingerprint"
            )
        return Contact(name=name, public=public, trust=trust)

    def get(self, fpr: bytes) -> Optional[Contact]:
        path = self._path_for(fpr)
        if not path.exists():
            return None
        return self._load_file(path)

    def require(self, fpr: bytes) -> Contact:
        contact = self.get(fpr)
        if contact is None:
            raise TrustError(
                f"no contact for fingerprint {format_fingerprint(fpr)}; "
                "import and verify it first"
            )
        return contact

    def by_name(self, name: str) -> Contact:
        validate_name(name)
        matches = [c for c in self.list() if c.name == name]
        if not matches:
            raise TrustError(f"no contact named '{name}'")
        if len(matches) > 1:
            raise TrustError(
                f"'{name}' is bound to {len(matches)} different keys; "
                "resolve it by fingerprint"
            )
        return matches[0]

    def resolve(self, selector: str) -> Contact:
        """Accept a fingerprint (grouped or plain hex) or a contact name."""
        try:
            fpr = parse_fingerprint(selector)
        except FormatError:
            return self.by_name(selector)
        return self.require(fpr)

    def list(self) -> list[Contact]:
        return sorted(self._iter(), key=lambda c: (c.name, c.fingerprint))

    def _iter(self) -> Iterator[Contact]:
        for path in sorted(self.directory.glob("*.contact")):
            yield self._load_file(path)

    # -- writing --

    def _write(self, contact: Contact) -> None:
        record = {
            "version": 1,
            "name": contact.name,
            "trust": contact.trust.value,
            "pubid": base64.b64encode(contact.public.pubid).decode("ascii"),
        }
        blob = json.dumps(record, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        with atomic_output(self._path_for(contact.fingerprint), overwrite=True) as fh:
            fh.write(blob)

    def import_contact(self, name: str, public: PublicIdentity) -> Contact:
        """Import a public identity under `name`, always as `unverified`.

        Re-importing the identical key is a no-op that preserves the existing
        trust state.  Importing a *different* key under a name that is already
        bound elsewhere is a key replacement: the new key is stored unverified,
        and the operator must verify it afresh.
        """
        validate_name(name)
        existing = self.get(public.fingerprint)
        if existing is not None:
            if existing.name != name:
                raise TrustError(
                    f"this key is already stored as '{existing.name}'; "
                    "remove it before importing it under a different name"
                )
            return existing

        replaced = [c for c in self.list() if c.name == name]
        contact = Contact(name=name, public=public, trust=Trust.UNVERIFIED)
        for old in replaced:
            # Invalidate old trust before publishing the replacement.  If an
            # intervening write fails, the old fingerprint must not remain
            # verified alongside a newly imported key.
            if old.trust is not Trust.REVOKED:
                self._write(Contact(old.name, old.public, Trust.UNVERIFIED))
        self._write(contact)
        return contact

    def verify_contact(self, fpr_or_name: str, presented_fingerprint: str) -> Contact:
        """Mark a contact verified, but only on a full fingerprint match."""
        contact = self.resolve(fpr_or_name)
        presented = parse_fingerprint(presented_fingerprint)
        if not fingerprints_equal(presented, contact.fingerprint):
            raise TrustError(
                "the fingerprint you entered does not match the stored key; "
                "the contact remains unverified"
            )
        if contact.trust is Trust.REVOKED:
            raise TrustError(
                f"contact '{contact.name}' is revoked; un-revoke it deliberately "
                "before verifying"
            )
        updated = Contact(contact.name, contact.public, Trust.VERIFIED)
        self._write(updated)
        return updated

    def set_trust(self, fpr_or_name: str, trust: Trust) -> Contact:
        contact = self.resolve(fpr_or_name)
        updated = Contact(contact.name, contact.public, trust)
        self._write(updated)
        return updated

    def revoke(self, fpr_or_name: str) -> Contact:
        return self.set_trust(fpr_or_name, Trust.REVOKED)

    def remove(self, fpr_or_name: str) -> Contact:
        contact = self.resolve(fpr_or_name)
        self._path_for(contact.fingerprint).unlink()
        return contact


__all__ = ["Contact", "ContactStore", "Trust", "validate_name"]
