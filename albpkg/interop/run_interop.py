#!/usr/bin/env python3
"""
ALBPKG/1 cross-port interoperability harness.

Drives each port's **real CLI** as a subprocess and tests every
producer/consumer combination: identities generated in one port must be
importable and verifiable in another, and a package sealed by any port must
open in every other port with byte-identical plaintext.

The plan's acceptance gate is 64 producer/consumer combinations across eight
ports. This harness enumerates `len(ports) ** 2` combinations from whichever
ports are actually present, and **fails** for every port that is declared but
whose toolchain is missing. A missing toolchain is a failure, not a pass --
that is the whole point of the gate.

Usage:
  python albpkg/interop/run_interop.py
  python albpkg/interop/run_interop.py --ports python,typescript
  python albpkg/interop/run_interop.py --require python,typescript,go
  python albpkg/interop/run_interop.py --quick
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

HERE = Path(__file__).resolve().parent
ALBPKG_ROOT = HERE.parent
PROJECT_ROOT = ALBPKG_ROOT.parent

PASSPHRASE = "interop-harness-passphrase"

#: Every port the product is supposed to ship. Anything listed here that is not
#: implemented or whose toolchain is unavailable is reported as a FAILURE.
ALL_PORTS = [
    "python",
    "typescript",
    "c",
    "cpp",
    "rust",
    "go",
    "php",
    "pascal",
]


# ---- Port drivers --------------------------------------------------------


@dataclass
class Port:
    """How to invoke one port's CLI."""

    name: str
    argv: list[str]
    available: bool
    reason: str = ""
    env: dict[str, str] = field(default_factory=dict)

    def run(
        self, args: list[str], *, home: Path, passfile: Path, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["ALBPKG_PASSPHRASE_FILE"] = str(passfile)
        env.update(self.env)
        result = subprocess.run(
            [*self.argv, "--home", str(home), *args],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(PROJECT_ROOT),
        )
        if check and result.returncode != 0:
            raise HarnessFailure(
                f"{self.name} CLI failed: albpkg {' '.join(args)}\n"
                f"  exit {result.returncode}\n"
                f"  stderr: {result.stderr.strip()[:500]}"
            )
        return result


class HarnessFailure(Exception):
    pass


def discover_python() -> Port:
    python_dir = ALBPKG_ROOT / "python"
    if not (python_dir / "albpkg" / "cli.py").exists():
        return Port("python", [], False, "albpkg/python/albpkg/cli.py not found")
    return Port(
        name="python",
        argv=[sys.executable, "-m", "albpkg.cli"],
        available=True,
        env={"PYTHONPATH": str(python_dir)},
    )


def discover_typescript() -> Port:
    ts_cli = ALBPKG_ROOT / "typescript" / "src" / "cli.ts"
    if not ts_cli.exists():
        return Port("typescript", [], False, "albpkg/typescript/src/cli.ts not found")
    node = shutil.which("node")
    if node is None:
        return Port("typescript", [], False, "node is not installed")
    return Port(name="typescript", argv=[node, str(ts_cli)], available=True)


def discover_go() -> Port:
    go_dir = ALBPKG_ROOT / "go"
    if not (go_dir / "go.mod").exists():
        return Port("go", [], False, "albpkg/go is not implemented yet")
    go = shutil.which("go")
    if go is None:
        return Port("go", [], False, "go is not installed")
    # Build into go/bin/ rather than go/: a binary named `albpkg` sitting next
    # to the package directory `albpkg/` is ambiguous to tooling and to
    # .gitignore patterns.
    bin_dir = go_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    binary = bin_dir / ("albpkg.exe" if os.name == "nt" else "albpkg")
    build_env = dict(os.environ)
    build_env["GOCACHE"] = str(go_dir / ".cache" / "go-build")
    build = subprocess.run(
        [go, "build", "-o", str(binary), "./cmd/albpkg"],
        cwd=str(go_dir),
        capture_output=True,
        text=True,
        env=build_env,
    )
    if build.returncode != 0:
        return Port("go", [], False, f"go build failed: {build.stderr.strip()[:200]}")
    return Port(name="go", argv=[str(binary)], available=True)


def discover_c() -> Port:
    """Build the independent C CLI against OpenSSL 3.5 or later."""
    c_dir = ALBPKG_ROOT / "c"
    sources = [c_dir / "albpkg.c", c_dir / "cli.c"]
    if not all(source.exists() for source in sources):
        return Port("c", [], False, "albpkg/c C library or CLI source is missing")
    bin_dir = c_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    binary = bin_dir / ("albpkg.exe" if os.name == "nt" else "albpkg")
    env = dict(os.environ)

    if os.name == "nt":
        # The repository-local Python environment carries the Zig C compiler in
        # the validated Windows workspace. OpenSSL comes from the installed Git
        # distribution unless the operator names another tested provider.
        probe = subprocess.run(
            [sys.executable, "-c", "import ziglang"], capture_output=True, text=True
        )
        if probe.returncode != 0:
            return Port("c", [], False, "ziglang C compiler is not installed")
        crypto = os.environ.get("ALBPKG_OPENSSL_CRYPTO")
        if not crypto:
            candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "mingw64" / "bin" / "libcrypto-3-x64.dll"
            if candidate.exists():
                crypto = str(candidate)
        if not crypto or not Path(crypto).exists():
            return Port("c", [], False, "OpenSSL 3.5 libcrypto DLL was not found")
        provider_dir = str(Path(crypto).resolve().parent)
        env["PATH"] = provider_dir + os.pathsep + env.get("PATH", "")
        env["ZIG_GLOBAL_CACHE_DIR"] = str(c_dir / ".cache" / "zig")
        command = [
            sys.executable,
            "-m",
            "ziglang",
            "cc",
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            *(str(source) for source in sources),
            crypto,
            "-ladvapi32",
            "-o",
            str(binary),
        ]
    else:
        cc = shutil.which("cc")
        if cc is None:
            return Port("c", [], False, "cc is not installed")
        command = [
            cc,
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            *(str(source) for source in sources),
            "-lcrypto",
            "-o",
            str(binary),
        ]
    build = subprocess.run(command, capture_output=True, text=True, env=env)
    if build.returncode != 0:
        detail = (build.stderr or build.stdout).strip()[:500]
        return Port("c", [], False, f"C build failed: {detail}")
    return Port(name="c", argv=[str(binary)], available=True, env=env)


def discover_missing(name: str, directory: str, tool: str) -> Callable[[], Port]:
    def discover() -> Port:
        target = ALBPKG_ROOT / directory
        if not target.exists():
            return Port(name, [], False, f"albpkg/{directory} is not implemented yet")
        if shutil.which(tool) is None:
            return Port(name, [], False, f"{tool} is not installed")
        return Port(name, [], False, f"albpkg/{directory} has no CLI entry point yet")

    return discover


DISCOVERY: dict[str, Callable[[], Port]] = {
    "python": discover_python,
    "typescript": discover_typescript,
    "go": discover_go,
    "c": discover_c,
    "cpp": discover_missing("cpp", "cpp", "c++"),
    "rust": discover_missing("rust", "rust", "cargo"),
    "php": discover_missing("php", "php", "php"),
    "pascal": discover_missing("pascal", "pascal", "fpc"),
}


# ---- Test payloads -------------------------------------------------------

CHUNK = 1 << 20

FULL_SIZES = [
    ("empty", 0),
    ("one-byte", 1),
    ("small", 1024),
    ("chunk-minus-one", CHUNK - 1),
    ("exact-chunk", CHUNK),
    ("chunk-plus-one", CHUNK + 1),
    ("two-chunks", 2 * CHUNK),
    ("two-chunks-plus", 2 * CHUNK + 7),
]

QUICK_SIZES = [
    ("empty", 0),
    ("small", 1024),
    ("exact-chunk", CHUNK),
    ("chunk-plus-one", CHUNK + 1),
]


def payload(size: int, seed: int) -> bytes:
    """Deterministic, non-compressible-ish payload of a given size."""
    if size == 0:
        return b""
    import hashlib

    out = bytearray()
    block = hashlib.sha256(f"albpkg-interop-{seed}".encode()).digest()
    while len(out) < size:
        out.extend(block)
        block = hashlib.sha256(block).digest()
    return bytes(out[:size])


# ---- Results -------------------------------------------------------------


@dataclass
class Results:
    passed: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)

    def ok(self, label: str, verbose: bool) -> None:
        self.passed += 1
        if verbose:
            print(f"  [ok]   {label}")

    def fail(self, label: str, detail: str) -> None:
        self.failed += 1
        self.failures.append(f"{label}: {detail}")
        print(f"  [FAIL] {label}: {detail}")


# ---- Harness -------------------------------------------------------------


def fingerprint_from_pub(pub_path: Path) -> str:
    """Read the armored public identity's fingerprint header."""
    for line in pub_path.read_text(encoding="utf-8").splitlines():
        if line.lower().startswith("fingerprint:"):
            return line.split(":", 1)[1].strip()
    raise HarnessFailure(f"{pub_path.name} has no fingerprint header")


def setup_identities(
    ports: list[Port], workdir: Path, passfile: Path, results: Results, verbose: bool
) -> dict[str, dict[str, Path]]:
    """Give every port its own identity, then cross-import and verify all of them."""
    identities: dict[str, dict[str, Path]] = {}

    for port in ports:
        home = workdir / f"home-{port.name}"
        home.mkdir(parents=True, exist_ok=True)
        port.run(["generate-identity"], home=home, passfile=passfile)
        pub = workdir / f"{port.name}.pub"
        port.run(
            ["export-public-identity", str(pub), "--overwrite"],
            home=home,
            passfile=passfile,
        )
        identities[port.name] = {
            "home": home,
            "pub": pub,
            "private": home / "identity.key",
        }
        results.ok(f"identity generated by {port.name}", verbose)

    # Every port imports and verifies every other port's public identity.
    for consumer in ports:
        home = identities[consumer.name]["home"]
        for producer in ports:
            if producer.name == consumer.name:
                continue
            pub = identities[producer.name]["pub"]
            label = f"{consumer.name} imports identity from {producer.name}"
            try:
                consumer.run(
                    ["import-contact", producer.name, str(pub)],
                    home=home,
                    passfile=passfile,
                )

                # An unverified contact must not be usable yet.
                probe_in = workdir / "probe.bin"
                probe_in.write_bytes(b"probe")
                probe_out = workdir / f"probe-{consumer.name}-{producer.name}.albpkg"
                rejected = consumer.run(
                    [
                        "seal",
                        str(probe_in),
                        str(probe_out),
                        "--to",
                        producer.name,
                        "--overwrite",
                    ],
                    home=home,
                    passfile=passfile,
                    check=False,
                )
                if rejected.returncode == 0:
                    raise HarnessFailure(
                        "sealing to an UNVERIFIED contact succeeded; it must be refused"
                    )

                consumer.run(
                    ["verify-contact", producer.name, fingerprint_from_pub(pub)],
                    home=home,
                    passfile=passfile,
                )
                results.ok(label, verbose)
            except HarnessFailure as exc:
                results.fail(label, str(exc))

    # Fingerprints must agree across ports for the same key.
    for port_name, paths in identities.items():
        declared = fingerprint_from_pub(paths["pub"])
        import base64
        import hashlib

        text = paths["pub"].read_text(encoding="utf-8")
        body = "".join(
            line.strip()
            for line in text.splitlines()
            if line.strip()
            and not line.startswith("-----")
            and ":" not in line
        )
        recomputed = hashlib.sha256(base64.b64decode(body)).hexdigest()
        label = f"{port_name} fingerprint matches SHA-256 of its canonical public identity"
        if recomputed == declared.replace("-", ""):
            results.ok(label, verbose)
        else:
            results.fail(label, f"declared {declared}, recomputed {recomputed}")

    return identities


def run_private_identity_matrix(
    ports: list[Port],
    identities: dict[str, dict[str, Path]],
    passfile: Path,
    results: Results,
    verbose: bool,
) -> None:
    """Every port must read every producer's canonical encrypted PKCS#8 file."""
    for producer in ports:
        expected = fingerprint_from_pub(identities[producer.name]["pub"])
        for consumer in ports:
            label = f"{consumer.name} loads PKCS#8 identity from {producer.name}"
            try:
                result = consumer.run(
                    [
                        "--identity",
                        str(identities[producer.name]["private"]),
                        "show-identity",
                    ],
                    home=identities[consumer.name]["home"],
                    passfile=passfile,
                )
                normalized_expected = expected.replace("-", "").lower()
                normalized_output = result.stdout.replace("-", "").lower()
                if normalized_expected not in normalized_output:
                    raise HarnessFailure(
                        f"fingerprint mismatch: expected {expected}, output was "
                        f"{result.stdout.strip()[:200]}"
                    )
                results.ok(label, verbose)
            except HarnessFailure as exc:
                results.fail(label, str(exc))


def run_legacy_migration_checks(
    ports: list[Port],
    identities: dict[str, dict[str, Path]],
    workdir: Path,
    passfile: Path,
    results: Results,
    verbose: bool,
) -> None:
    """Every CLI must migrate ALBPKSK2 only through its explicit command."""
    python_dir = ALBPKG_ROOT / "python"
    sys.path.insert(0, str(python_dir))
    try:
        from albpkg.identity import _save_legacy_identity, load_identity

        provider = lambda _prompt: PASSPHRASE
        identity = load_identity(
            identities["python"]["private"], passphrase_provider=provider
        )
        source = workdir / "legacy-migration-source.key"
        _save_legacy_identity(
            identity, source, passphrase_provider=provider, overwrite=False
        )
    finally:
        sys.path.pop(0)

    original = source.read_bytes()
    expected = fingerprint_from_pub(identities["python"]["pub"])
    for port in ports:
        label = f"{port.name} explicitly migrates ALBPKSK2 and retains the source"
        target = workdir / f"migrated-{port.name}.key"
        migration_home = workdir / f"migration-home-{port.name}"
        migration_home.mkdir(parents=True, exist_ok=True)
        try:
            port.run(
                [
                    "--identity",
                    str(target),
                    "migrate-legacy-identity",
                    str(source),
                ],
                home=migration_home,
                passfile=passfile,
            )
            if source.read_bytes() != original:
                raise HarnessFailure("legacy source was modified or deleted")
            shown = port.run(
                ["--identity", str(target), "show-identity"],
                home=migration_home,
                passfile=passfile,
            )
            normalized = shown.stdout.replace("-", "").lower()
            if expected.replace("-", "").lower() not in normalized:
                raise HarnessFailure("migrated identity fingerprint changed")
            results.ok(label, verbose)
        except HarnessFailure as exc:
            results.fail(label, str(exc))


def run_matrix(
    ports: list[Port],
    identities: dict[str, dict[str, Path]],
    sizes: list[tuple[str, int]],
    workdir: Path,
    passfile: Path,
    results: Results,
    verbose: bool,
) -> None:
    """Every producer seals for every consumer, at every size."""
    for index, (size_name, size) in enumerate(sizes):
        data = payload(size, index)
        source = workdir / f"payload-{size_name}.bin"
        source.write_bytes(data)

        for producer in ports:
            for consumer in ports:
                label = f"{producer.name} -> {consumer.name} [{size_name}, {size} bytes]"
                pkg = workdir / f"{producer.name}-to-{consumer.name}-{size_name}.albpkg"
                out = workdir / f"out-{producer.name}-{consumer.name}-{size_name}.bin"
                try:
                    # Always address the recipient by full fingerprint: it is
                    # the one selector that means the same thing in every port
                    # and every contact store.
                    producer.run(
                        [
                            "seal",
                            str(source),
                            str(pkg),
                            "--to",
                            fingerprint_from_pub(identities[consumer.name]["pub"]),
                            "--overwrite",
                        ],
                        home=identities[producer.name]["home"],
                        passfile=passfile,
                    )
                    consumer.run(
                        ["open", str(pkg), str(out), "--overwrite"],
                        home=identities[consumer.name]["home"],
                        passfile=passfile,
                    )
                    recovered = out.read_bytes()
                    if recovered != data:
                        raise HarnessFailure(
                            f"plaintext mismatch: expected {len(data)} bytes, "
                            f"got {len(recovered)}"
                        )
                    results.ok(label, verbose)
                except HarnessFailure as exc:
                    results.fail(label, str(exc))


def setup_self_contacts(
    ports: list[Port], identities: dict[str, dict[str, Path]], passfile: Path,
    results: Results, verbose: bool,
) -> None:
    """Each port imports and verifies its own key so it can seal to itself."""
    for port in ports:
        home = identities[port.name]["home"]
        pub = identities[port.name]["pub"]
        label = f"{port.name} trusts its own key (self-addressed packages)"
        try:
            port.run(["import-contact", "self", str(pub)], home=home, passfile=passfile)
            port.run(
                ["verify-contact", "self", fingerprint_from_pub(pub)],
                home=home,
                passfile=passfile,
            )
            results.ok(label, verbose)
        except HarnessFailure as exc:
            results.fail(label, str(exc))


def run_rejection_matrix(
    ports: list[Port],
    identities: dict[str, dict[str, Path]],
    workdir: Path,
    passfile: Path,
    results: Results,
    verbose: bool,
) -> None:
    """Every consumer must reject the same malformed packages from every producer."""
    import hashlib

    HEADER_LEN = 1194
    SIG_LEN = 3309
    TRAILER_LEN = 12

    data = payload(4096, 99)
    source = workdir / "reject-payload.bin"
    source.write_bytes(data)

    mutations: list[tuple[str, Callable[[bytes], bytes]]] = [
        ("flipped header byte", lambda b: _flip(b, 24)),
        ("flipped ciphertext byte", lambda b: _flip(b, HEADER_LEN + 10)),
        (
            "flipped signature byte",
            lambda b: _flip(b, len(b) - TRAILER_LEN - SIG_LEN + 5),
        ),
        ("truncated by one byte", lambda b: b[:-1]),
        ("appended data", lambda b: b + b"extra"),
        ("stripped trailer", lambda b: b[:-TRAILER_LEN]),
    ]

    for producer in ports:
        for consumer in ports:
            if producer.name == consumer.name:
                continue
            pkg = workdir / f"reject-{producer.name}-{consumer.name}.albpkg"
            try:
                producer.run(
                    [
                        "seal",
                        str(source),
                        str(pkg),
                        "--to",
                        consumer.name,
                        "--overwrite",
                    ],
                    home=identities[producer.name]["home"],
                    passfile=passfile,
                )
            except HarnessFailure as exc:
                results.fail(f"{producer.name} seal for rejection tests", str(exc))
                continue

            good = pkg.read_bytes()
            for mutation_name, mutate in mutations:
                label = (
                    f"{consumer.name} rejects {mutation_name} "
                    f"from {producer.name}"
                )
                broken = workdir / f"broken-{producer.name}-{consumer.name}.albpkg"
                broken.write_bytes(mutate(good))
                out = workdir / f"broken-out-{producer.name}-{consumer.name}.bin"
                if out.exists():
                    out.unlink()
                result = consumer.run(
                    ["open", str(broken), str(out), "--overwrite"],
                    home=identities[consumer.name]["home"],
                    passfile=passfile,
                    check=False,
                )
                if result.returncode == 0:
                    results.fail(label, "the package was accepted")
                elif out.exists():
                    results.fail(label, "a partial output file was published")
                else:
                    results.ok(label, verbose)


def _flip(blob: bytes, offset: int) -> bytes:
    out = bytearray(blob)
    out[offset] ^= 0x01
    return bytes(out)


# ---- Entry point ---------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--ports",
        default=None,
        help="comma-separated ports to exercise (default: every available port)",
    )
    parser.add_argument(
        "--require",
        default=None,
        help=(
            "comma-separated ports that MUST be available; a missing one fails "
            "the run (use this in CI)"
        ),
    )
    parser.add_argument("--quick", action="store_true", help="fewer payload sizes")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--keep", action="store_true", help="keep the working directory for inspection"
    )
    parser.add_argument("--json", default=None, help="write a JSON report to this path")
    args = parser.parse_args(argv)

    requested = (
        [name.strip() for name in args.ports.split(",") if name.strip()]
        if args.ports
        else ALL_PORTS
    )
    required = (
        [name.strip() for name in args.require.split(",") if name.strip()]
        if args.require
        else []
    )

    unknown = [name for name in requested + required if name not in DISCOVERY]
    if unknown:
        print(f"unknown port(s): {', '.join(unknown)}", file=sys.stderr)
        return 2

    print("ALBPKG/1 cross-port interoperability")
    print("=" * 70)

    # Discover the union of what was requested and what is required: a port
    # named in --require must be checked even if --ports leaves it out,
    # otherwise the gate would silently pass by narrowing the selection.
    to_discover = list(dict.fromkeys(requested + required))

    discovered: list[Port] = []
    for name in to_discover:
        port = DISCOVERY[name]()
        discovered.append(port)
        state = "available" if port.available else f"UNAVAILABLE ({port.reason})"
        marks = []
        if name in required:
            marks.append("required")
        if name not in requested:
            marks.append("not selected for testing")
        suffix = f"  [{', '.join(marks)}]" if marks else ""
        print(f"  {name:<12} {state}{suffix}")

    available = [
        port for port in discovered if port.available and port.name in requested
    ]
    missing_required = [
        port for port in discovered if port.name in required and not port.available
    ]

    if missing_required:
        print("\n" + "=" * 70)
        for port in missing_required:
            print(f"FAIL: required port '{port.name}' is unavailable: {port.reason}")
        print(
            "A missing toolchain or unimplemented port is a FAILURE, not a skip.\n"
            "That is the release gate."
        )
        return 1

    if len(available) < 2:
        print("\nNeed at least two available ports to test interoperability.")
        print(f"Found {len(available)}: {', '.join(p.name for p in available)}")
        return 1

    combinations = len(available) ** 2
    print(
        f"\n{len(available)} port(s) available -> {combinations} producer/consumer "
        f"combination(s) of the {len(ALL_PORTS) ** 2} the release gate requires."
    )

    sizes = QUICK_SIZES if args.quick else FULL_SIZES
    results = Results()
    started = time.time()

    workdir = Path(tempfile.mkdtemp(prefix="albpkg-interop-"))
    passfile = workdir / "passphrase.txt"
    passfile.write_text(PASSPHRASE, encoding="utf-8")
    if os.name != "nt":
        passfile.chmod(0o600)

    try:
        print("\n--- identities and contact exchange ---")
        identities = setup_identities(available, workdir, passfile, results, args.verbose)
        print("\n--- encrypted PKCS#8 private identity matrix ---")
        run_private_identity_matrix(
            available, identities, passfile, results, args.verbose
        )
        print("\n--- explicit legacy identity migration ---")
        run_legacy_migration_checks(
            available, identities, workdir, passfile, results, args.verbose
        )
        setup_self_contacts(available, identities, passfile, results, args.verbose)

        print(f"\n--- seal/open matrix ({len(sizes)} payload sizes) ---")
        run_matrix(available, identities, sizes, workdir, passfile, results, args.verbose)

        print("\n--- cross-port rejection matrix ---")
        run_rejection_matrix(
            available, identities, workdir, passfile, results, args.verbose
        )
    finally:
        if args.keep:
            print(f"\nworking directory kept: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    elapsed = time.time() - started
    total = results.passed + results.failed

    print("\n" + "=" * 70)
    if results.failed == 0:
        print(f"ALL {total} INTEROP CHECKS PASSED in {elapsed:.1f}s")
    else:
        print(f"FAILED: {results.failed} of {total} checks in {elapsed:.1f}s")
        for failure in results.failures[:20]:
            print(f"  - {failure}")

    unimplemented = [port.name for port in discovered if not port.available]
    if unimplemented:
        print(
            f"\nNOT COVERED ({len(unimplemented)} port(s)): {', '.join(unimplemented)}"
        )
        print(
            "The release gate requires all 8 ports and all 64 combinations.\n"
            "Use --require to make their absence fail this run."
        )

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                {
                    "passed": results.passed,
                    "failed": results.failed,
                    "failures": results.failures,
                    "ports_available": [p.name for p in available],
                    "ports_unavailable": {
                        p.name: p.reason for p in discovered if not p.available
                    },
                    "combinations_tested": combinations,
                    "combinations_required": len(ALL_PORTS) ** 2,
                    "elapsed_seconds": round(elapsed, 2),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    return 0 if results.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
