#!/usr/bin/env python3
"""Compile and run the checked C512 research API regression."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "c" / "test_checked_api.c"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="c512-checked-api-") as temporary:
        output = Path(temporary) / (
            "checked-api.exe" if os.name == "nt" else "checked-api"
        )
        env = dict(os.environ)
        if os.name == "nt":
            command = [
                sys.executable,
                "-m",
                "ziglang",
                "cc",
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-function",
                str(SOURCE),
                "-o",
                str(output),
            ]
            env["ZIG_GLOBAL_CACHE_DIR"] = str(ROOT / ".cache" / "zig-checked-api")
        else:
            cc = shutil.which("cc")
            if not cc:
                raise SystemExit("required C compiler cc is not installed")
            command = [
                cc,
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wno-unused-function",
                str(SOURCE),
                "-o",
                str(output),
            ]
        subprocess.run(command, cwd=ROOT, env=env, check=True)
        subprocess.run([str(output)], cwd=ROOT, env=env, check=True)
        if os.name == "nt":
            output32 = Path(temporary) / "checked-api-x86.exe"
            command32 = command.copy()
            command32[4:4] = ["-target", "x86-windows-gnu"]
            command32[-1] = str(output32)
            subprocess.run(command32, cwd=ROOT, env=env, check=True)
            subprocess.run([str(output32)], cwd=ROOT, env=env, check=True)
    print(
        "C512 checked-API capacity, overlap, overflow, auth cleanup, and "
        "allocation regressions passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
