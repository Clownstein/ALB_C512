#!/usr/bin/env python3
"""Explicitly migrate one bounded C512 research fixture to ALBPKG/1.

This is deliberately a separate tool. The production ALBPKG parser never
autodetects or falls back to C512. The original artifact is retained.
"""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import struct
import sys


TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT / "python"))
sys.path.insert(0, str(PROJECT_ROOT / "albpkg" / "python"))

from c512 import C512_KEY_SIZE, C512_NONCE_SIZE, C512_TAG_SIZE, decrypt
from albpkg.contacts import ContactStore
from albpkg.fsutil import permissions_are_owner_only, private_spool, wipe
from albpkg.identity import load_identity
from albpkg.package import seal_file


MAGIC = b"C512"
VERSION = 1
MAX_PLAINTEXT = 16 << 20
MAX_AAD = 1 << 16
FIXED_HEADER = 4 + 2 + 4 + C512_NONCE_SIZE + 4


def _read_line_from_fd(fd: int) -> str:
    with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
        return handle.readline(1025).rstrip("\r\n")


def _load_research_key(path: str | None, fd: int | None) -> bytearray:
    if (path is None) == (fd is None):
        raise ValueError("supply exactly one of --key-file or --key-fd")
    if path is not None:
        if not permissions_are_owner_only(Path(path)):
            raise ValueError("research key file permissions are not owner-only")
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.readline(130).strip()
    else:
        text = _read_line_from_fd(int(fd)).strip()
    try:
        key = bytearray.fromhex(text)
    except ValueError as exc:
        raise ValueError("research key is not valid hex") from exc
    if len(key) != C512_KEY_SIZE:
        wipe(key)
        raise ValueError(
            f"research key must be exactly {C512_KEY_SIZE * 2} hex characters"
        )
    return key


def _identity_passphrase_provider(fd: int | None):
    if fd is not None:
        return lambda _prompt: _read_line_from_fd(fd)
    named = os.environ.get("ALBPKG_PASSPHRASE_FILE")
    if named:
        def from_file(_prompt: str) -> str:
            with open(named, "r", encoding="utf-8") as handle:
                return handle.readline(1025).rstrip("\r\n")
        return from_file
    return lambda prompt: getpass.getpass(f"{prompt}: ")


def read_and_decrypt(source: Path, key: bytes) -> bytearray:
    """Strictly parse the legacy demo frame and authenticate its payload."""
    with source.open("rb") as handle:
        header = handle.read(FIXED_HEADER)
        if len(header) != FIXED_HEADER:
            raise ValueError("truncated C512 demo header")
        magic, version, plaintext_len = struct.unpack("<4sHI", header[:10])
        if magic != MAGIC or version != VERSION:
            raise ValueError("unsupported C512 demo magic or version")
        if plaintext_len > MAX_PLAINTEXT:
            raise ValueError("C512 demo plaintext length exceeds 16 MiB")
        nonce = header[10 : 10 + C512_NONCE_SIZE]
        aad_len = struct.unpack("<I", header[-4:])[0]
        if aad_len > MAX_AAD:
            raise ValueError("C512 demo AAD length exceeds 64 KiB")
        aad = handle.read(aad_len)
        if len(aad) != aad_len:
            raise ValueError("truncated C512 demo AAD")
        expected = plaintext_len + C512_TAG_SIZE
        sealed = handle.read(expected + 1)
        if len(sealed) != expected:
            raise ValueError("C512 demo payload length disagrees with its header")

    try:
        plaintext = bytearray(decrypt(key, nonce, aad, sealed))
    except Exception as exc:
        raise ValueError("C512 authentication failed; refusing migration") from exc
    if len(plaintext) != plaintext_len:
        wipe(plaintext)
        raise ValueError("authenticated plaintext length disagrees with the frame")
    return plaintext


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="legacy .c512 artifact")
    parser.add_argument("output", type=Path, help="new ALBPKG/1 package")
    parser.add_argument("--key-file")
    parser.add_argument("--key-fd", type=int)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--identity-passphrase-fd", type=int)
    parser.add_argument("--to", required=True, help="verified recipient name or fingerprint")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument(
        "--experimental",
        action="store_true",
        required=True,
        help="acknowledge that the source format is insecure research code",
    )
    args = parser.parse_args(argv)

    if args.source.resolve() == args.output.resolve():
        parser.error("source and destination must be different paths")
    if not args.source.is_file():
        parser.error("source is not a regular file")
    if args.output.exists() and not args.overwrite:
        parser.error("destination exists; pass --overwrite to replace it")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    os.environ["ALB_C512_EXPERIMENTAL"] = "1"
    key = _load_research_key(args.key_file, args.key_fd)
    plaintext: bytearray | None = None
    try:
        plaintext = read_and_decrypt(args.source, bytes(key))
        identity_path = args.identity or args.home / "identity.key"
        identity = load_identity(
            identity_path,
            passphrase_provider=_identity_passphrase_provider(
                args.identity_passphrase_fd
            ),
        )
        recipient = ContactStore(args.home / "contacts").resolve(args.to)
        recipient.require_usable()

        with private_spool(args.output.parent) as (scratch, scratch_path):
            scratch.write(plaintext)
            scratch.flush()
            os.fsync(scratch.fileno())
            result = seal_file(
                sender=identity,
                recipient=recipient,
                input_path=scratch_path,
                output_path=args.output,
                overwrite=args.overwrite,
            )
    finally:
        wipe(key)
        if plaintext is not None:
            wipe(plaintext)

    print(f"migrated {result.total_bytes} authenticated plaintext bytes")
    print(f"new package: {result.package_path}")
    print(f"original retained: {args.source}")
    print("C512 was used only by this explicit migration tool; ALBPKG has no fallback.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
