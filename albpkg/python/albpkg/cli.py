"""`albpkg` command line interface.

Passphrases are never accepted as arguments.  They come from a no-echo prompt,
or -- for automation -- from a file descriptor or a file named by
``ALBPKG_PASSPHRASE_FILE``, never from ``argv`` and never from a log line.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .contacts import ContactStore, Trust
from .errors import AlbpkgError, PassphraseError
from .identity import (
    Identity,
    PublicIdentity,
    export_public_identity,
    generate_identity,
    load_identity,
    migrate_legacy_identity,
    prompt_passphrase,
    save_identity,
)
from .package import open_file, seal_file
from .suite import CHUNK_SIZE, SUITE_NAME

DEFAULT_HOME = Path(
    os.environ.get("ALBPKG_HOME", Path.home() / ".albpkg")
).expanduser()


# ---- Passphrase sourcing -------------------------------------------------


def _passphrase_provider(args: argparse.Namespace):
    """Build a passphrase provider from the non-argv sources only."""
    if getattr(args, "passphrase_fd", None) is not None:
        fd = args.passphrase_fd

        def from_fd(_prompt: str) -> str:
            try:
                with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
                    return handle.readline().rstrip("\r\n")
            except OSError as exc:
                raise PassphraseError(f"cannot read passphrase from fd {fd}") from exc

        return from_fd

    env_file = os.environ.get("ALBPKG_PASSPHRASE_FILE")
    if env_file:
        path = Path(env_file)

        def from_file(_prompt: str) -> str:
            try:
                return path.read_text(encoding="utf-8").splitlines()[0]
            except (OSError, IndexError) as exc:
                raise PassphraseError(
                    "cannot read the passphrase file named by ALBPKG_PASSPHRASE_FILE"
                ) from exc

        return from_file

    return None  # interactive no-echo prompt


def _store(args: argparse.Namespace) -> ContactStore:
    return ContactStore(Path(args.home) / "contacts")


def _identity_path(args: argparse.Namespace) -> Path:
    return Path(args.identity) if args.identity else Path(args.home) / "identity.key"


def _load(args: argparse.Namespace) -> Identity:
    return load_identity(
        _identity_path(args), passphrase_provider=_passphrase_provider(args)
    )


def _progress(label: str):
    if not sys.stderr.isatty():
        return None

    state = {"last": 0}

    def hook(done: int, chunks: int) -> None:
        mib = done / (1 << 20)
        if chunks - state["last"] >= 16 or chunks <= 1:
            state["last"] = chunks
            print(f"\r{label}: {mib:.1f} MiB ({chunks} chunks)", end="", file=sys.stderr)

    return hook


def _end_progress() -> None:
    if sys.stderr.isatty():
        print(file=sys.stderr)


# ---- Commands ------------------------------------------------------------


def cmd_generate_identity(args: argparse.Namespace) -> int:
    path = _identity_path(args)
    path.parent.mkdir(parents=True, exist_ok=True)
    identity = generate_identity()
    save_identity(
        identity,
        path,
        passphrase_provider=_passphrase_provider(args),
        overwrite=args.overwrite,
    )
    print(f"identity written to {path}")
    print(f"suite:       {SUITE_NAME}")
    print(f"fingerprint: {identity.public.fingerprint_text}")
    print(
        "\nGive the full fingerprint to your contacts over a channel you already "
        "trust.\nThey must compare all 64 characters before they can use your key."
    )
    return 0


def cmd_export_public_identity(args: argparse.Namespace) -> int:
    identity = _load(args)
    out = Path(args.output)
    fpr = export_public_identity(identity, out, overwrite=args.overwrite)
    print(f"public identity written to {out}")
    print(f"fingerprint: {fpr}")
    return 0


def cmd_show_identity(args: argparse.Namespace) -> int:
    identity = _load(args)
    print(f"suite:       {SUITE_NAME}")
    print(f"fingerprint: {identity.public.fingerprint_text}")
    return 0


def cmd_migrate_legacy_identity(args: argparse.Namespace) -> int:
    source = Path(args.source)
    target = _identity_path(args)
    if source.resolve() == target.resolve():
        raise IOErrorAlbpkg("legacy source and PKCS#8 destination must be different paths")
    identity = migrate_legacy_identity(
        source,
        target,
        passphrase_provider=_passphrase_provider(args),
        overwrite=args.overwrite,
    )
    print(f"migrated identity written to {target}")
    print(f"original retained at {source}")
    print(f"fingerprint: {identity.public.fingerprint_text}")
    return 0


def cmd_import_contact(args: argparse.Namespace) -> int:
    store = _store(args)
    text = Path(args.file).read_text(encoding="utf-8")
    public = PublicIdentity.from_armored(text)
    contact = store.import_contact(args.name, public)
    print(f"imported '{contact.name}' as {contact.trust.value}")
    print(f"fingerprint: {contact.fingerprint_text}")
    print(
        "\nThis contact is UNVERIFIED and cannot be used yet.\n"
        "Confirm the fingerprint above with them over a separate, trusted channel,\n"
        f"then run:  albpkg verify-contact {contact.name} <fingerprint>"
    )
    return 0


def cmd_verify_contact(args: argparse.Namespace) -> int:
    store = _store(args)
    contact = store.verify_contact(args.contact, args.fingerprint)
    print(f"'{contact.name}' is now verified")
    print(f"fingerprint: {contact.fingerprint_text}")
    return 0


def cmd_list_contacts(args: argparse.Namespace) -> int:
    contacts = _store(args).list()
    if not contacts:
        print("no contacts")
        return 0
    width = max(len(c.name) for c in contacts)
    for contact in contacts:
        print(f"{contact.name:<{width}}  {contact.trust.value:<10}  {contact.fingerprint_text}")
    return 0


def cmd_revoke_contact(args: argparse.Namespace) -> int:
    contact = _store(args).revoke(args.contact)
    print(f"'{contact.name}' is revoked and will be rejected from now on")
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    identity = _load(args)
    contact = _store(args).resolve(args.to)
    result = seal_file(
        sender=identity,
        recipient=contact,
        input_path=args.input,
        output_path=args.output,
        overwrite=args.overwrite,
        progress=_progress("sealing"),
    )
    _end_progress()
    print(f"sealed {result.total_bytes} bytes in {result.chunk_count} chunks")
    print(f"package:     {result.package_path}")
    print(f"package id:  {result.package_id_hex}")
    print(f"recipient:   {contact.name}  {result.recipient_fingerprint}")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    identity = _load(args)
    result = open_file(
        recipient=identity,
        contacts=_store(args),
        package_path=args.input,
        output_path=args.output,
        overwrite=args.overwrite,
        progress=_progress("opening"),
    )
    _end_progress()
    print(f"opened {result.total_bytes} bytes in {result.chunk_count} chunks")
    print(f"output:      {result.output_path}")
    print(f"package id:  {result.package_id_hex}")
    print(f"sender:      {result.sender_name}  {result.sender_fingerprint}")
    return 0


# ---- Parser --------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="albpkg",
        description=(
            f"Signed post-quantum file packages ({SUITE_NAME}: ML-KEM-768, "
            f"ML-DSA-65, HKDF-SHA-256, AES-256-GCM). Chunk size {CHUNK_SIZE} bytes."
        ),
        epilog=(
            "Passphrases are never read from the command line. Use the interactive "
            "prompt, --passphrase-fd, or ALBPKG_PASSPHRASE_FILE."
        ),
    )
    parser.add_argument("--version", action="version", version=f"albpkg {__version__}")
    parser.add_argument(
        "--home",
        default=str(DEFAULT_HOME),
        help="configuration directory (default: %(default)s)",
    )
    parser.add_argument(
        "--identity", default=None, help="private identity file (default: <home>/identity.key)"
    )
    parser.add_argument(
        "--passphrase-fd",
        type=int,
        default=None,
        metavar="FD",
        help="read the passphrase from this file descriptor instead of prompting",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("generate-identity", help="create a new identity keypair set")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_generate_identity)

    p = sub.add_parser("export-public-identity", help="write your shareable public identity")
    p.add_argument("output")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_export_public_identity)

    p = sub.add_parser("show-identity", help="print your own fingerprint")
    p.set_defaults(func=cmd_show_identity)

    p = sub.add_parser(
        "migrate-legacy-identity",
        help="explicitly convert an ALBPKSK2 file to encrypted PKCS#8",
    )
    p.add_argument("source", help="legacy ALBPKSK2 identity file")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_migrate_legacy_identity)

    p = sub.add_parser("import-contact", help="import a contact's public identity")
    p.add_argument("name")
    p.add_argument("file")
    p.set_defaults(func=cmd_import_contact)

    p = sub.add_parser(
        "verify-contact", help="confirm a contact's full fingerprint out of band"
    )
    p.add_argument("contact", help="contact name or fingerprint")
    p.add_argument("fingerprint", help="the full 64-hex fingerprint they gave you")
    p.set_defaults(func=cmd_verify_contact)

    p = sub.add_parser("list-contacts", help="list contacts and their trust state")
    p.set_defaults(func=cmd_list_contacts)

    p = sub.add_parser("revoke-contact", help="locally revoke a contact")
    p.add_argument("contact")
    p.set_defaults(func=cmd_revoke_contact)

    p = sub.add_parser("seal", help="encrypt and sign a file for one verified contact")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--to", required=True, help="recipient contact name or fingerprint")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("open", help="verify and decrypt a package")
    p.add_argument("input")
    p.add_argument("output")
    p.add_argument("--overwrite", action="store_true")
    p.set_defaults(func=cmd_open)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AlbpkgError as exc:
        _end_progress()
        print(f"albpkg: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        _end_progress()
        print("albpkg: cancelled; no output was published", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
