#!/usr/bin/env python3
"""
Build a release archive from validated source, with a manifest and hashes.

This replaces the hand-made ALB_C512.zip, which had drifted from the source
tree and shipped *less secure* code than the repository contained: a Pascal
nonce generator built from `Byte(Random(256))`, a C rotation that shifted by
32 when the rotation amount was zero, SIV allocation failures that could
leave nonce output uninitialized, incompatible Pascal constants, and stale
Python bytecode caches.

An archive built here:

  * is generated from the working tree, never edited by hand;
  * excludes caches, build output, virtualenvs, and VCS metadata;
  * refuses to run unless the required test suites have just passed;
  * carries MANIFEST.json listing every file with its SHA-256, plus a
    top-level SHA-256 of the archive itself.

Usage:
  python tools/make_release.py --out dist/
  python tools/make_release.py --out dist/ --skip-tests   # local dry run only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent

EXCLUDE_DIRS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".claude",
}

EXCLUDE_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".obj",
    ".o",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".zip",
    ".secret",
    ".key",
    ".tmp",
}

EXCLUDE_NAMES = {
    "albpkg.exe",
    "albpkg",
    "test_key.secret",
    "test_meta.json",
    "test_plain.bin",
    "test_encrypted.c512",
}

#: Suites that must pass before an archive may be produced.  A missing
#: toolchain is a failure, not a pass: an archive is only as trustworthy as
#: the checks that actually ran against the source going into it.
ALBPKG_ROOT = PROJECT_ROOT / "albpkg"

#: Ports that must be present and passing before an archive may be produced.
#: Extend this list as each port lands; a port named here that is missing or
#: broken fails the release.
RELEASE_PORTS = ["c", "cpp", "rust", "go", "python", "php", "pascal", "typescript"]

# This gate may be changed only after the review evidence and resolution of
# findings are committed. Tests or an operator flag cannot establish review.
INDEPENDENT_REVIEW_COMPLETE = False

REQUIRED_CHECKS = [
    (
        "albpkg python acceptance suite",
        [sys.executable, "-m", "pytest", str(ALBPKG_ROOT / "python" / "tests"), "-q"],
    ),
    (
        "albpkg typescript acceptance suite",
        ["node", "--test", str(ALBPKG_ROOT / "typescript" / "tests")],
    ),
    (
        "albpkg go acceptance suite",
        ["go", "test", "./..."],
        {"cwd": str(ALBPKG_ROOT / "go")},
    ),
    (
        "albpkg C warnings and focused interoperability suite",
        [sys.executable, str(ALBPKG_ROOT / "c" / "run_checks.py")],
    ),
    (
        "albpkg cross-port interoperability",
        [
            sys.executable,
            str(ALBPKG_ROOT / "interop" / "run_interop.py"),
            "--ports",
            ",".join(RELEASE_PORTS),
            "--require",
            ",".join(RELEASE_PORTS),
        ],
    ),
    (
        "C512 research vectors (python)",
        [sys.executable, str(TOOLS_DIR / "test_vectors_v2_verify.py"), "--lite"],
    ),
    (
        "C512 structural-defect regressions",
        [sys.executable, str(TOOLS_DIR / "c512_structural_regressions.py")],
    ),
    (
        "C512 checked C API regressions",
        [sys.executable, str(TOOLS_DIR / "run_c_checked_api.py")],
    ),
    (
        "C512 research CLI secret-handling regressions",
        [
            sys.executable,
            "-m",
            "pytest",
            str(TOOLS_DIR / "test_research_cli.py"),
            "-q",
        ],
    ),
    (
        "explicit C512-to-ALBPKG migration regression",
        [
            sys.executable,
            "-m",
            "pytest",
            str(TOOLS_DIR / "test_c512_migration.py"),
            "-q",
        ],
    ),
]


def iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            if name in EXCLUDE_NAMES:
                continue
            path = Path(dirpath) / name
            if path.is_symlink():
                raise SystemExit(f"refusing to archive a symbolic link: {path}")
            if path.suffix.lower() in EXCLUDE_SUFFIXES:
                continue
            yield path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def run_checks() -> None:
    env = dict(os.environ)
    env["ALB_C512_EXPERIMENTAL"] = "1"  # the research vectors need the opt-in
    for check in REQUIRED_CHECKS:
        label, command = check[0], check[1]
        extra = check[2] if len(check) > 2 else {}
        cwd = extra.get("cwd", str(PROJECT_ROOT))
        print(f"[*] {label}")
        try:
            result = subprocess.run(command, cwd=cwd, env=env)
        except FileNotFoundError:
            raise SystemExit(
                f"[FAIL] {label}: the required tool is not installed.\n"
                "       A missing toolchain fails the release; it does not count as a pass."
            )
        if result.returncode != 0:
            raise SystemExit(f"[FAIL] {label}: exit {result.returncode}; no archive produced")
        print(f"[ok]  {label}")


def build(out_dir: Path, skip_tests: bool) -> Path:
    if skip_tests:
        print(
            "[!] --skip-tests: this archive is a LOCAL DRY RUN and must not be\n"
            "    distributed. The manifest records that checks were skipped."
        )
    else:
        if not INDEPENDENT_REVIEW_COMPLETE:
            raise SystemExit(
                "Release blocked: independent cryptographic and per-port security "
                "reviews have not been completed. Local dry-run archives remain "
                "available with --skip-tests and are not releases."
            )
        run_checks()

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d", time.gmtime())
    kind = "UNVALIDATED-SOURCE-" if skip_tests else ""
    archive = out_dir / f"ALB_C512-{kind}{stamp}.zip"
    if archive.exists():
        raise SystemExit(f"{archive} already exists; remove it or pick another --out")

    files = list(iter_source_files(PROJECT_ROOT))
    entries = []
    for path in files:
        rel = path.relative_to(PROJECT_ROOT).as_posix()
        entries.append(
            {"path": rel, "size": path.stat().st_size, "sha256": sha256_file(path)}
        )

    manifest = {
        "name": "ALB_C512",
        "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks_run": not skip_tests,
        "release_eligible": not skip_tests and INDEPENDENT_REVIEW_COMPLETE,
        "independent_review_complete": INDEPENDENT_REVIEW_COMPLETE,
        "checks": [check[0] for check in REQUIRED_CHECKS] if not skip_tests else [],
        "ports_verified": RELEASE_PORTS if not skip_tests else [],
        "notice": (
            "ALB_C512 (C512, C512-Lite, C512-SIV, C512-XOF) is RESEARCH ONLY and "
            "must not be used to protect real information. The albpkg/ directory "
            "is an incomplete package-encryption review candidate (ML-KEM-768, "
            "ML-DSA-65, HKDF-SHA-256, AES-256-GCM via maintained providers). "
            "It is not approved to protect real information."
        ),
        "file_count": len(entries),
        "files": entries,
    }

    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, entry in zip(files, entries):
            data = path.read_bytes()
            if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise SystemExit(f"source changed during archive creation: {path}")
            zf.writestr(f"ALB_C512/{entry['path']}", data)
        zf.writestr(
            "ALB_C512/MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True)
        )

    digest = sha256_file(archive)
    (out_dir / f"{archive.name}.sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )

    print(f"\n[+] {archive}")
    print(f"[+] {len(entries)} files, sha256 {digest}")
    return archive


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--out", default=str(PROJECT_ROOT / "dist"))
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="local dry run only; the resulting archive must not be distributed",
    )
    args = parser.parse_args(argv)
    build(Path(args.out), args.skip_tests)
    return 0


if __name__ == "__main__":
    sys.exit(main())
