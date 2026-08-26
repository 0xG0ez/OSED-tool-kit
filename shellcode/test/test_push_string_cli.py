import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class PushStringCliTests(unittest.TestCase):
    def run_cli(self, script, *arguments):
        return subprocess.run(
            [sys.executable, str(ROOT / script), *arguments],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_push_string_accepts_badchars_in_documented_format(self):
        result = self.run_cli(
            "push_string.py",
            "kernel32.dll",
            "-b",
            r"\x00\x0a\x0d\x25\x26\x2b\x3d",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "\n".join(
                [
                    "xor eax, eax;",
                    "push eax;",
                    "push 0x6c6c642e;",
                    "push 0x32336c65;",
                    "push 0x6e72656b;",
                    "",
                ]
            ),
        )

    def test_push_dword_accepts_hex_and_register(self):
        result = self.run_cli("push_dword.py", "0x41424344", "-r", "ecx", "-b", r"\x00")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "push 0x41424344;\n")

    def test_negative_add_generates_assembly(self):
        result = self.run_cli(
            "negative_add.py", "0x41414141", "-r", "ecx", "-b", r"\x00\x41\xbe\xbf", "--max-count", "4"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("xor ecx, ecx;", result.stdout)
        self.assertIn("push ecx;", result.stdout)

    def test_invalid_badchars_fail_cleanly(self):
        result = self.run_cli("push_string.py", "kernel32.dll", "-b", "00")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(r"must use \xNN notation", result.stderr)

    def test_out_of_range_dword_fails_cleanly(self):
        result = self.run_cli("push_dword.py", "0x100000000")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dword must be between", result.stderr)


if __name__ == "__main__":
    unittest.main()
