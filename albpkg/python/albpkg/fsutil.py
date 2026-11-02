"""Private temporary files, owner-only permissions, atomic publication.

FORMAT.md section 7.  Nothing partially written ever appears at a destination
path: work happens in an owner-only temporary file in the destination directory
(so the final rename stays on one filesystem) and is published by rename only
after every check has passed.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
from pathlib import Path
from typing import BinaryIO, Iterator

from .errors import IOErrorAlbpkg

_IS_WINDOWS = sys.platform == "win32"


def restrict_permissions(path: Path) -> None:
    """Make `path` readable and writable by its owner only.

    On POSIX this is chmod 0600.  On Windows we replace the DACL with a single
    ACE for the current user via `icacls`, disabling inheritance.  If the
    platform call is unavailable we surface the failure rather than pretending
    the file is protected.
    """
    if not _IS_WINDOWS:
        os.chmod(path, 0o600)
        return

    import subprocess

    # Resolve the actual access-token SID, not spoofable environment names.
    import re
    who = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
    match = re.search(r"S-1-[0-9-]+", who)
    if match is None:
        raise IOErrorAlbpkg("cannot determine current user SID")
    principal = "*" + match.group(0)
    try:
        result = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{principal}:F"],
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise IOErrorAlbpkg("failed to restrict file permissions") from exc
    if result.returncode != 0:
        raise IOErrorAlbpkg("failed to restrict file permissions")


def permissions_are_owner_only(path: Path) -> bool:
    """Best-effort check used by tests and by the key loader's warning path."""
    if not _IS_WINDOWS:
        return (os.stat(path).st_mode & 0o077) == 0
    import subprocess

    try:
        result = subprocess.run(
            ["icacls", str(path)], capture_output=True, check=False, text=True
        )
    except OSError:
        return False
    if result.returncode != 0:
        return False
    lines = [ln for ln in result.stdout.splitlines() if ":(" in ln]
    for bad in ("Everyone", "BUILTIN\\Users", "Authenticated Users"):
        if any(bad in ln for ln in lines):
            return False
    return True


def open_private_new(path: Path) -> BinaryIO:
    """Create `path` exclusively with owner-only permissions and open it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if _IS_WINDOWS:
        flags |= os.O_BINARY  # type: ignore[attr-defined]
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise
    except OSError as exc:
        raise IOErrorAlbpkg(f"cannot create {path.name}") from exc
    try:
        if _IS_WINDOWS:
            restrict_permissions(path)
        return os.fdopen(fd, "wb")
    except Exception:
        with contextlib.suppress(OSError):
            os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def _temp_sibling(destination: Path) -> Path:
    return destination.parent / f".{destination.name}.albpkg-{secrets.token_hex(8)}.tmp"


@contextlib.contextmanager
def atomic_output(destination: Path, *, overwrite: bool = False) -> Iterator[BinaryIO]:
    """Yield a private temp file; publish it atomically on clean exit.

    On any exception the temporary file is removed and `destination` is left
    exactly as it was.  Without `overwrite`, an existing destination causes a
    failure *before* any work is done and is never touched.
    """
    destination = Path(destination)
    parent = destination.parent
    if not parent.exists():
        raise IOErrorAlbpkg(f"destination directory does not exist: {parent}")
    if destination.exists() and not overwrite:
        raise IOErrorAlbpkg(
            f"destination exists and overwrite was not requested: {destination.name}"
        )

    tmp = _temp_sibling(destination)
    for _ in range(8):
        try:
            handle = open_private_new(tmp)
            break
        except FileExistsError:
            tmp = _temp_sibling(destination)
    else:  # pragma: no cover - 2^256 collisions
        raise IOErrorAlbpkg("could not create a unique temporary file")

    published = False
    try:
        yield handle
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        if overwrite:
            os.replace(tmp, destination)
        else:
            # link is atomic and fails if another writer created destination.
            os.link(tmp, destination)
            os.unlink(tmp)
        published = True
    finally:
        with contextlib.suppress(Exception):
            if not handle.closed:
                handle.close()
        if not published:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


@contextlib.contextmanager
def private_spool(directory: Path) -> Iterator[tuple[BinaryIO, Path]]:
    """An owner-only scratch file that is always deleted.

    Yields the open write handle and its path; the caller may reopen the path
    for reading while the handle is still held.
    """
    tmp = directory / f".albpkg-spool-{secrets.token_hex(8)}.tmp"
    handle = open_private_new(tmp)
    try:
        yield handle, tmp
    finally:
        with contextlib.suppress(Exception):
            if not handle.closed:
                handle.close()
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def wipe(buffer: bytearray) -> None:
    """Overwrite a mutable secret buffer in place.

    This is best-effort.  On a managed runtime it cannot reach copies the
    interpreter made (interned bytes, GC-moved blocks, swap).  Ports in C, C++,
    and Rust use their platform's guaranteed-erasure call instead.
    """
    for i in range(len(buffer)):
        buffer[i] = 0


__all__ = [
    "atomic_output",
    "open_private_new",
    "permissions_are_owner_only",
    "private_spool",
    "restrict_permissions",
    "wipe",
]
