#!/usr/bin/env python3
"""Build the C port with warnings-as-errors and run its focused interop suite."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent


def command_for(output: Path, *, cli: bool, sanitize: bool) -> tuple[list[str], dict[str, str]]:
    sources = [HERE / "albpkg.c"]
    if cli:
        sources.append(HERE / "cli.c")
    env = dict(os.environ)
    flags = ["-std=c99", "-Wall", "-Wextra", "-Werror"]
    if sanitize:
        flags.append("-fsanitize=address,undefined")

    if os.name == "nt":
        probe = subprocess.run(
            [sys.executable, "-c", "import ziglang"], capture_output=True, text=True
        )
        if probe.returncode:
            raise RuntimeError("ziglang C compiler is not installed")
        crypto = os.environ.get("ALBPKG_OPENSSL_CRYPTO")
        if not crypto:
            candidate = (
                Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
                / "Git"
                / "mingw64"
                / "bin"
                / "libcrypto-3-x64.dll"
            )
            if candidate.exists():
                crypto = str(candidate)
        if not crypto or not Path(crypto).exists():
            raise RuntimeError("OpenSSL 3.5 libcrypto DLL was not found")
        env["PATH"] = str(Path(crypto).resolve().parent) + os.pathsep + env.get(
            "PATH", ""
        )
        env["ZIG_GLOBAL_CACHE_DIR"] = str(HERE / ".cache" / "zig-checks")
        command = [
            sys.executable,
            "-m",
            "ziglang",
            "cc",
            *flags,
        ]
        if not cli:
            command.append("-shared")
        command.extend(str(source) for source in sources)
        command.extend([crypto, "-ladvapi32", "-o", str(output)])
        return command, env

    cc = shutil.which("cc")
    if cc is None:
        raise RuntimeError("cc is not installed")
    command = [cc, *flags]
    if not cli:
        command.extend(["-fPIC", "-shared"])
    command.extend(str(source) for source in sources)
    command.extend(["-lcrypto", "-o", str(output)])
    return command, env


def run(command: list[str], env: dict[str, str]) -> None:
    result = subprocess.run(command, env=env)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sanitizers",
        action="store_true",
        help="also run an ASan/UBSan CLI identity and package smoke",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="albpkg-c-check-") as temporary:
        root = Path(temporary)
        library = root / ("albpkg.dll" if os.name == "nt" else "libalbpkg.so")
        command, env = command_for(library, cli=False, sanitize=False)
        run(command, env)
        test = [sys.executable, str(HERE / "test_interop.py"), str(library)]
        if os.name == "nt":
            test.append(str(Path(env["PATH"].split(os.pathsep, 1)[0])))
        run(test, env)

        if args.sanitizers:
            cli = root / ("albpkg-sanitized.exe" if os.name == "nt" else "albpkg-sanitized")
            command, env = command_for(cli, cli=True, sanitize=True)
            run(command, env)
            passfile = root / "passphrase.txt"
            passfile.write_text("sanitizer passphrase value\n", encoding="utf-8")
            if os.name != "nt":
                passfile.chmod(0o600)
            smoke_env = dict(env)
            smoke_env["ALBPKG_PASSPHRASE_FILE"] = str(passfile)
            home = root / "home"
            run([str(cli), "--home", str(home), "generate-identity"], smoke_env)
            run([str(cli), "--home", str(home), "show-identity"], smoke_env)
            public = root / "self.pub"
            run(
                [str(cli), "--home", str(home), "export-public-identity", str(public)],
                smoke_env,
            )
            fingerprint = next(
                line.split(":", 1)[1].strip()
                for line in public.read_text(encoding="utf-8").splitlines()
                if line.startswith("fingerprint:")
            )
            run(
                [str(cli), "--home", str(home), "import-contact", "self", str(public)],
                smoke_env,
            )
            run(
                [str(cli), "--home", str(home), "verify-contact", "self", fingerprint],
                smoke_env,
            )
            plaintext = root / "plain.bin"
            package = root / "package.albpkg"
            opened = root / "opened.bin"
            plaintext.write_bytes(bytes(range(256)) * 4097)
            run(
                [
                    str(cli),
                    "--home",
                    str(home),
                    "seal",
                    str(plaintext),
                    str(package),
                    "--to",
                    "self",
                ],
                smoke_env,
            )
            run(
                [
                    str(cli),
                    "--home",
                    str(home),
                    "open",
                    str(package),
                    str(opened),
                ],
                smoke_env,
            )
            if opened.read_bytes() != plaintext.read_bytes():
                raise SystemExit("sanitized C package round-trip changed the plaintext")

    print("C warnings-as-errors and focused interoperability checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
