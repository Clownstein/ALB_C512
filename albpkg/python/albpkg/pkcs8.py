"""Strict encrypted PKCS#8 profile used for ALBPKG private keys.

The key object is standard PKCS#8 EncryptedPrivateKeyInfo using PBES2,
PBKDF2-HMAC-SHA-256, and AES-256-CBC. Cryptographic operations come from
``cryptography``; this module only implements the narrow ASN.1 DER profile so
all language ports emit identical, bounded parameters.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .errors import FormatError, LimitError, PassphraseError

SALT_LEN = 16
IV_LEN = 16
MIN_ITERATIONS = 600_000
MAX_ITERATIONS = 10_000_000
DEFAULT_ITERATIONS = 600_000
MAX_DER_LEN = 4096

_OID_PBES2 = bytes.fromhex("2a864886f70d01050d")
_OID_PBKDF2 = bytes.fromhex("2a864886f70d01050c")
_OID_HMAC_SHA256 = bytes.fromhex("2a864886f70d0209")
_OID_AES256_CBC = bytes.fromhex("60864801650304012a")


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def _seq(*values: bytes) -> bytes:
    return _tlv(0x30, b"".join(values))


def _oid(value: bytes) -> bytes:
    return _tlv(0x06, value)


def _octets(value: bytes) -> bytes:
    return _tlv(0x04, value)


def _integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\x00" + encoded
    return _tlv(0x02, encoded)


class _Reader:
    def __init__(self, data: bytes, label: str = "PKCS#8") -> None:
        self.data = data
        self.offset = 0
        self.label = label

    def tlv(self, tag: int, field: str) -> bytes:
        if self.offset >= len(self.data) or self.data[self.offset] != tag:
            raise FormatError(f"noncanonical {self.label}: expected {field}")
        self.offset += 1
        if self.offset >= len(self.data):
            raise FormatError(f"truncated {self.label} length")
        first = self.data[self.offset]
        self.offset += 1
        if first < 0x80:
            size = first
        else:
            count = first & 0x7F
            if count == 0 or count > 4 or self.offset + count > len(self.data):
                raise FormatError(f"invalid {self.label} length")
            raw = self.data[self.offset : self.offset + count]
            self.offset += count
            if raw[0] == 0 or (count == 1 and raw[0] < 0x80):
                raise FormatError(f"noncanonical {self.label} length")
            size = int.from_bytes(raw, "big")
        if self.offset + size > len(self.data):
            raise FormatError(f"truncated {field}")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def sequence(self, field: str) -> "_Reader":
        return _Reader(self.tlv(0x30, field), field)

    def oid(self, expected: bytes, field: str) -> None:
        if self.tlv(0x06, field) != expected:
            raise FormatError(f"unsupported {field}")

    def integer(self, field: str) -> int:
        raw = self.tlv(0x02, field)
        if not raw or raw[0] & 0x80 or (len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80):
            raise FormatError(f"noncanonical {field}")
        return int.from_bytes(raw, "big")

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise FormatError(f"trailing bytes in {self.label}")


def encrypt_private_key_info(
    private_key_info: bytes,
    passphrase: bytes,
    *,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise LimitError(
            f"iteration count must be between {MIN_ITERATIONS} and {MAX_ITERATIONS}"
        )
    if not private_key_info or len(private_key_info) > MAX_DER_LEN:
        raise LimitError("private key information has an invalid size")
    salt, iv = os.urandom(SALT_LEN), os.urandom(IV_LEN)
    key = bytearray(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
        ).derive(passphrase)
    )
    padder = padding.PKCS7(128).padder()
    padded = bytearray(padder.update(private_key_info) + padder.finalize())
    try:
        encryptor = Cipher(algorithms.AES(bytes(key)), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(bytes(padded)) + encryptor.finalize()
    finally:
        key[:] = b"\x00" * len(key)
        padded[:] = b"\x00" * len(padded)
    prf = _seq(_oid(_OID_HMAC_SHA256), _tlv(0x05, b""))
    pbkdf2 = _seq(_oid(_OID_PBKDF2), _seq(_octets(salt), _integer(iterations), prf))
    cipher = _seq(_oid(_OID_AES256_CBC), _octets(iv))
    return _seq(_seq(_oid(_OID_PBES2), _seq(pbkdf2, cipher)), _octets(ciphertext))


def decrypt_private_key_info(blob: bytes, passphrase: bytes) -> bytes:
    if not blob or len(blob) > MAX_DER_LEN:
        raise LimitError("encrypted PKCS#8 object has an invalid size")
    root = _Reader(blob)
    outer = root.sequence("EncryptedPrivateKeyInfo")
    algorithm = outer.sequence("encryption algorithm")
    algorithm.oid(_OID_PBES2, "encryption algorithm OID")
    params = algorithm.sequence("PBES2 parameters")
    kdf = params.sequence("key derivation function")
    kdf.oid(_OID_PBKDF2, "key derivation OID")
    kdf_params = kdf.sequence("PBKDF2 parameters")
    salt = kdf_params.tlv(0x04, "PBKDF2 salt")
    if len(salt) != SALT_LEN:
        raise FormatError("PBKDF2 salt must be 16 bytes")
    iterations = kdf_params.integer("PBKDF2 iteration count")
    if not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise LimitError(
            f"iteration count {iterations} is outside the permitted range "
            f"[{MIN_ITERATIONS}, {MAX_ITERATIONS}]"
        )
    prf = kdf_params.sequence("PBKDF2 PRF")
    prf.oid(_OID_HMAC_SHA256, "PBKDF2 PRF OID")
    if prf.tlv(0x05, "PBKDF2 PRF NULL parameters"):
        raise FormatError("PBKDF2 PRF parameters must be NULL")
    prf.finish()
    kdf_params.finish()
    kdf.finish()
    cipher = params.sequence("encryption scheme")
    cipher.oid(_OID_AES256_CBC, "encryption scheme OID")
    iv = cipher.tlv(0x04, "AES-CBC IV")
    if len(iv) != IV_LEN:
        raise FormatError("AES-CBC IV must be 16 bytes")
    cipher.finish()
    params.finish()
    algorithm.finish()
    ciphertext = outer.tlv(0x04, "encrypted private key")
    outer.finish()
    root.finish()
    if not ciphertext or len(ciphertext) > MAX_DER_LEN or len(ciphertext) % 16:
        raise FormatError("encrypted private key has a noncanonical length")
    key = bytearray(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations
        ).derive(passphrase)
    )
    plaintext = bytearray()
    try:
        decryptor = Cipher(algorithms.AES(bytes(key)), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        try:
            plaintext.extend(unpadder.update(padded) + unpadder.finalize())
        except ValueError as exc:
            raise PassphraseError(
                "could not decrypt the private key; the passphrase is wrong "
                "or the key has been altered"
            ) from exc
    finally:
        key[:] = b"\x00" * len(key)
    if not plaintext or len(plaintext) > MAX_DER_LEN:
        plaintext[:] = b"\x00" * len(plaintext)
        raise FormatError("decrypted private key has an invalid size")
    result = bytes(plaintext)
    plaintext[:] = b"\x00" * len(plaintext)
    return result
