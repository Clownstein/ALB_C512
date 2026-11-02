"""Regression checks for research CLI secret handling and deliberate opt-in."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ResearchCliTests(unittest.TestCase):
    def run_cli(self, script, *args):
        env = dict(os.environ)
        env.pop("ALB_C512_EXPERIMENTAL", None)
        return subprocess.run([sys.executable, "-B", str(ROOT / script), *map(str, args)],
                              env=env, capture_output=True, text=True)

    def test_secret_arguments_are_rejected(self):
        result = self.run_cli("python/c512.py", "encrypt", "--key", "00" * 64)
        self.assertNotEqual(result.returncode, 0)

    def test_demo_requires_opt_in_and_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.c512"
            for args in ((), ("--experimental",)):
                result = self.run_cli("tools/c512_encrypt_file.py", *args, "--output", output)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_demo_saves_key_without_logging_it(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.c512"
            result = self.run_cli("tools/c512_encrypt_file.py", "--experimental", "--save-key",
                                  "--size", "1", "--output", output)
            self.assertEqual(result.returncode, 0, result.stderr)
            key = (Path(directory) / "test_key.secret").read_text()
            self.assertEqual(len(bytes.fromhex(key)), 64)
            self.assertNotIn(key[:32], result.stdout + result.stderr)
            self.assertTrue(output.exists())
            again = self.run_cli("tools/c512_encrypt_file.py", "--experimental", "--save-key",
                                 "--size", "1", "--output", output)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual((Path(directory) / "test_key.secret").read_text(), key)


if __name__ == "__main__":
    unittest.main()
