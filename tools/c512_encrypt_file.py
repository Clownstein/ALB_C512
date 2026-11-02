"""
C512 File Encryptor -- RESEARCH FIXTURE GENERATOR, NOT A FILE ENCRYPTOR.

Builds a C512-AEAD test artifact for the cryptanalysis tooling.  C512 has
known structural defects (see SECURITY.md); this script must never be used
to protect real information. The separate albpkg/ candidate also awaits review.

Secret handling in this tool:

  * The key is NEVER printed, in whole or in part.  It previously logged
    ``key.hex()[:32]`` and ``key.hex()[-8:]`` -- 160 of its 512 bits -- to
    stdout on every run.
  * A key is NEVER accepted as a command-line argument, because argv is
    visible in shell history and to any process that can read /proc or the
    Windows process list.  Supply one with --key-file or --key-fd.
  * Generating a key requires --save-key so the artifact remains recoverable.
  * No plaintext digest is written.  The old metadata carried
    ``plaintext_sha256``, which lets anyone holding the "encrypted" file
    confirm a plaintext guess without touching the cipher at all.
  * Key files are created with owner-only permissions and are never
    silently overwritten.

Usage:
  python c512_encrypt_file.py [--plaintext FILE] [--key-file FILE]
                              [--output FILE] [--save-key]
"""

import os
import stat
import sys
import json
import time
import struct
import hashlib  # used only to seed the deterministic test plaintext, never for secrets
import argparse
import subprocess

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "python"))
from c512 import encrypt, C512_KEY_SIZE, C512_NONCE_SIZE, C512_TAG_SIZE


RESEARCH_BANNER = (
    "=" * 70 + "\n"
    "  ALB_C512 RESEARCH FIXTURE -- NOT SECURE, NOT FOR REAL DATA.\n"
    "  C512's core permutation is not a permutation; colliding inputs are\n"
    "  reproduced in tools/c512_structural_regressions.py.\n"
    + "=" * 70
)


def _restrict(path):
    """Make a file owner-readable only, on POSIX and on Windows."""
    if os.name != "nt":
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return
    import re
    identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True)
    sid = re.search(r"S-1-[0-9-]+", identity.stdout)
    if not sid:
        raise SystemExit("cannot determine the current user to restrict key file access")
    principal = "*" + sid.group(0)
    result = subprocess.run(
        ["icacls", path, "/inheritance:r", "/grant:r", f"{principal}:F"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"could not restrict permissions on {path}; refusing to write a key there")


def _read_key_from_fd(fd):
    with os.fdopen(os.dup(fd), "r", encoding="utf-8") as handle:
        return handle.readline(130).strip()


def _load_key(args):
    """Load a key from a file or a file descriptor -- never from argv."""
    if args.key_file and args.key_fd is not None:
        raise SystemExit("give --key-file or --key-fd, not both")
    if args.key_file:
        with open(args.key_file, "r", encoding="utf-8") as handle:
            text = handle.readline(130).strip()
    elif args.key_fd is not None:
        text = _read_key_from_fd(args.key_fd)
    else:
        return None
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise SystemExit("key material is not valid hex")
    if len(key) != C512_KEY_SIZE:
        raise SystemExit(f"key must be exactly {C512_KEY_SIZE} bytes ({C512_KEY_SIZE * 2} hex characters)")
    return key

# ── File format ─────────────────────────────────────────────────────────────
# Header (magic + version + metadata) then encrypted payload
#
# [4B magic "C512"]
# [2B version 0x0001]
# [4B plaintext_length]
# [32B nonce]
# [4B aad_length]
# [NB aad]
# [... ciphertext + tag ...]

MAGIC = b'C512'
VERSION = 0x0001


def write_encrypted_file(path, nonce, aad, ct_tag, pt_len):
    with open(path, 'wb') as f:
        f.write(MAGIC)
        f.write(struct.pack('<H', VERSION))
        f.write(struct.pack('<I', pt_len))
        f.write(nonce)
        f.write(struct.pack('<I', len(aad)))
        f.write(aad)
        f.write(ct_tag)


def generate_test_plaintext(size=4096):
    """Generate structured plaintext with known patterns for analysis."""
    parts = []

    header = (
        b"=== ALB_C512 Test Plaintext ===\n"
        b"This file was generated to test the security of the C512 cipher.\n"
        b"It contains structured data, repeated patterns, and randomness.\n"
        b"Timestamp: " + str(int(time.time())).encode() + b"\n"
        b"=" * 60 + b"\n\n"
    )
    parts.append(header)

    parts.append(b"AAAA" * 64)
    parts.append(b"\n")

    parts.append(bytes(range(256)))
    parts.append(b"\n")

    parts.append(b"\x00" * 256)
    parts.append(b"\n")

    parts.append(b"\xff" * 256)
    parts.append(b"\n")

    english = (
        b"The quick brown fox jumps over the lazy dog. "
        b"Pack my box with five dozen liquor jugs. "
        b"How vexingly quick daft zebras jump. "
        b"The five boxing wizards jump quickly. "
        b"Sphinx of black quartz, judge my vow. "
    ) * 3
    parts.append(english)
    parts.append(b"\n")

    rng = hashlib.sha256(b"c512_test_seed")
    random_block = b""
    while len(random_block) < 512:
        rng = hashlib.sha256(rng.digest())
        random_block += rng.digest()
    parts.append(random_block[:512])

    data = b"".join(parts)
    if len(data) < size:
        while len(data) < size:
            rng = hashlib.sha256(rng.digest())
            data += rng.digest()
    return data[:size]


def main():
    parser = argparse.ArgumentParser(
        description="C512 Test File Encryptor"
    )
    parser.add_argument(
        "--plaintext", default=None,
        help="Path to plaintext file (generated if omitted)"
    )
    # There is deliberately no --key option. A key passed in argv lands in
    # shell history and is readable by any process that can list command
    # lines. Use --key-file or --key-fd instead.
    parser.add_argument(
        "--output", default="test_encrypted.c512",
        help="Output encrypted file path"
    )
    parser.add_argument(
        "--size", type=int, default=4096,
        help="Generated plaintext size in bytes (default 4096)"
    )
    parser.add_argument(
        "--aad", default="C512-test-encryption",
        help="Associated authenticated data string"
    )
    parser.add_argument(
        "--save-key", action="store_true",
        help="Write the key to test_key.secret with owner-only permissions"
    )
    parser.add_argument(
        "--key-file", default=None,
        help="Read a hex key from this file (never pass a key on the command line)"
    )
    parser.add_argument(
        "--key-fd", type=int, default=None,
        help="Read a hex key from this file descriptor"
    )
    parser.add_argument(
        "--overwrite", action="store_true",
        help="Allow existing output, metadata, and key files to be replaced"
    )
    parser.add_argument("--experimental", action="store_true", required=True,
                        help="Acknowledge that C512 is research-only and not secure")
    args = parser.parse_args()
    os.environ["ALB_C512_EXPERIMENTAL"] = "1"
    if not 0 <= args.size <= 16 << 20:
        parser.error("research plaintext size must be between 0 and 16 MiB")

    print(RESEARCH_BANNER)

    out_dir = os.path.dirname(os.path.abspath(args.output))

    key = _load_key(args)
    generated = key is None
    if generated:
        key = os.urandom(C512_KEY_SIZE)
        if not args.save_key:
            raise SystemExit("Generated keys must be retained: pass --save-key or supply --key-file/--key-fd.")

    candidates = [args.output, os.path.join(out_dir, "test_meta.json")]
    if not args.plaintext:
        candidates.append(os.path.join(out_dir, "test_plain.bin"))
    if args.save_key:
        candidates.append(os.path.join(out_dir, "test_key.secret"))
    for candidate in candidates:
        if os.path.exists(candidate) and not args.overwrite:
            raise SystemExit(f"{candidate} exists; pass --overwrite to replace it")

    if args.plaintext:
        with open(args.plaintext, 'rb') as f:
            plaintext = f.read((16 << 20) + 1)
        if len(plaintext) > 16 << 20:
            raise SystemExit("research plaintext limit is 16 MiB")
    else:
        plaintext = generate_test_plaintext(args.size)
        pt_path = os.path.join(out_dir, "test_plain.bin")
        with open(pt_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] Plaintext written: {pt_path} ({len(plaintext)} bytes)")

    nonce = os.urandom(C512_NONCE_SIZE)
    aad = args.aad.encode('utf-8')

    t0 = time.perf_counter()
    ct_tag = encrypt(key, nonce, aad, plaintext)
    elapsed = time.perf_counter() - t0

    write_encrypted_file(args.output, nonce, aad, ct_tag, len(plaintext))
    enc_size = os.path.getsize(args.output)
    print(f"[+] Encrypted file: {args.output} ({enc_size} bytes)")
    print(f"[+] Encryption time: {elapsed*1000:.1f} ms")

    meta = {
        "algorithm": "ALB_C512",
        "key_size_bits": C512_KEY_SIZE * 8,
        "nonce_hex": nonce.hex(),
        "aad_hex": aad.hex(),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ct_tag) - C512_TAG_SIZE,
        "tag_size": C512_TAG_SIZE,
        "encrypted_file": os.path.basename(args.output),
        # No plaintext digest: publishing one alongside the ciphertext lets an
        # observer confirm a plaintext guess without attacking the cipher.
        "timestamp": int(time.time()),
        "warning": "ALB_C512 is research-only and not secure. Do not use for real data.",
    }
    meta_path = os.path.join(out_dir, "test_meta.json")
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)
    print(f"[+] Metadata written: {meta_path}")

    if args.save_key:
        key_path = os.path.join(out_dir, "test_key.secret")
        if os.path.exists(key_path) and not args.overwrite:
            raise SystemExit(f"{key_path} exists; pass --overwrite to replace it")
        fd = os.open(
            key_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as f:
            _restrict(key_path)
            f.write(key.hex().encode("ascii"))
        print(f"[+] Key saved with owner-only permissions: {key_path}")
    elif not generated:
        print("[*] Key was supplied by the caller and is not written back.")

    # The key is deliberately absent from this summary. Printing any part of
    # it -- the old code printed 160 of its 512 bits -- puts it in terminal
    # scrollback, shell logs, and CI output.
    print(f"\n{'='*60}")
    print(f"  Key:        NOT DISPLAYED (see --save-key)")
    print(f"  Nonce:      {nonce.hex()}")
    print(f"  PT size:    {len(plaintext)} bytes")
    print(f"  CT+Tag:     {len(ct_tag)} bytes")
    print(f"  Overhead:   {len(ct_tag) - len(plaintext)} bytes (tag only)")
    print(f"{'='*60}")
    print(RESEARCH_BANNER)


if __name__ == '__main__':
    main()
