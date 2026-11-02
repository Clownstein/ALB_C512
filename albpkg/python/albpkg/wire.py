"""Canonical big-endian serialization with checked arithmetic.

The reader here is deliberately strict: every read is exact, every length is
bounds-checked before it is used to size anything, and finishing a structure
requires that no trailing bytes remain.  Ports in memory-unsafe languages must
mirror `checked_add` / `checked_mul` literally.
"""

from __future__ import annotations

import io
from typing import BinaryIO

from .errors import FormatError, IOErrorAlbpkg, LimitError
from .suite import UINT32_MAX, UINT64_MAX

# ---- Checked arithmetic --------------------------------------------------


def checked_add(a: int, b: int, *, limit: int = UINT64_MAX, what: str = "length") -> int:
    if a < 0 or b < 0:
        raise LimitError(f"negative {what}")
    total = a + b
    if total > limit:
        raise LimitError(f"{what} overflow: {a} + {b} exceeds {limit}")
    return total


def checked_mul(a: int, b: int, *, limit: int = UINT64_MAX, what: str = "length") -> int:
    if a < 0 or b < 0:
        raise LimitError(f"negative {what}")
    total = a * b
    if total > limit:
        raise LimitError(f"{what} overflow: {a} * {b} exceeds {limit}")
    return total


# ---- Encoding ------------------------------------------------------------


def u8(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FormatError("u8 requires an int")
    if not 0 <= value <= 0xFF:
        raise LimitError("u8 out of range")
    return value.to_bytes(1, "big")


def u16(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FormatError("u16 requires an int")
    if not 0 <= value <= 0xFFFF:
        raise LimitError("u16 out of range")
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FormatError("u32 requires an int")
    if not 0 <= value <= UINT32_MAX:
        raise LimitError("u32 out of range")
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool):
        raise FormatError("u64 requires an int")
    if not 0 <= value <= UINT64_MAX:
        raise LimitError("u64 out of range")
    return value.to_bytes(8, "big")


# ---- Exact stream reads --------------------------------------------------

#: Refuse to allocate a single read larger than this.  Every caller that reads a
#: length-prefixed field checks the length against its own bound first; this is
#: the backstop for the ones that do not.
MAX_SINGLE_READ = 64 << 20  # 64 MiB


def read_exact(stream: BinaryIO, n: int, what: str) -> bytes:
    """Read exactly `n` bytes or raise.  A short read is a format error."""
    if n < 0:
        raise LimitError(f"negative read length for {what}")
    if n > MAX_SINGLE_READ:
        raise LimitError(f"refusing to read {n} bytes for {what}")
    if n == 0:
        return b""
    buf = bytearray(n)
    view = memoryview(buf)
    got = 0
    while got < n:
        try:
            k = stream.readinto(view[got:])  # type: ignore[attr-defined]
        except AttributeError:  # stream without readinto
            piece = stream.read(n - got)
            k = len(piece) if piece else 0
            if k:
                view[got : got + k] = piece
        except OSError as exc:
            raise IOErrorAlbpkg(f"read failed for {what}") from exc
        if not k:
            raise FormatError(f"truncated input: wanted {n} bytes for {what}, got {got}")
        got += k
    return bytes(buf)


class ByteReader:
    """Bounds-checked cursor over an in-memory buffer.

    Cursor-based rather than slice-and-reassign: repeated re-slicing of a large
    buffer is quadratic, which is the defect recorded against the research
    streaming API.
    """

    __slots__ = ("_buf", "_pos", "_name")

    def __init__(self, data: bytes, name: str = "input") -> None:
        self._buf = data
        self._pos = 0
        self._name = name

    @property
    def offset(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def take(self, n: int, what: str) -> bytes:
        if n < 0:
            raise LimitError(f"negative length for {what}")
        end = checked_add(self._pos, n, what=f"{what} offset")
        if end > len(self._buf):
            raise FormatError(
                f"truncated {self._name}: {what} needs {n} bytes, "
                f"{self.remaining} remain"
            )
        out = self._buf[self._pos : end]
        self._pos = end
        return out

    def u8(self, what: str) -> int:
        return self.take(1, what)[0]

    def u16(self, what: str) -> int:
        return int.from_bytes(self.take(2, what), "big")

    def u32(self, what: str) -> int:
        return int.from_bytes(self.take(4, what), "big")

    def u64(self, what: str) -> int:
        return int.from_bytes(self.take(8, what), "big")

    def expect(self, literal: bytes, what: str) -> None:
        got = self.take(len(literal), what)
        if got != literal:
            raise FormatError(f"bad {what}")

    def finish(self) -> None:
        if self.remaining:
            raise FormatError(
                f"trailing bytes in {self._name}: {self.remaining} unconsumed"
            )


def is_seekable(stream: BinaryIO) -> bool:
    try:
        if not stream.seekable():
            return False
    except (AttributeError, OSError, ValueError):
        return False
    try:
        stream.tell()
    except (OSError, ValueError, io.UnsupportedOperation):
        return False
    return True


__all__ = [
    "ByteReader",
    "checked_add",
    "checked_mul",
    "is_seekable",
    "read_exact",
    "u16",
    "u32",
    "u64",
    "u8",
]
