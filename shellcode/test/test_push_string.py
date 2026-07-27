import unittest

from shellcode.push_string import push_string


class PushStringTests(unittest.TestCase):
    def test_cmd_exe_uses_null_terminated_tail_without_space_padding(self):
        self.assertEqual(
            push_string("cmd.exe"),
            "\n".join(
                [
                    "mov eax, 0xff9a879b;",
                    "neg eax;",
                    "push eax;",
                    "push 0x2e646d63;",
                ]
            ),
        )

    def test_ws2_32_dll_does_not_emit_redundant_null_dword(self):
        self.assertEqual(
            push_string("ws2_32.dll"),
            "\n".join(
                [
                    "xor eax, eax;",
                    "mov ax, 0x6c6c;",
                    "push eax;",
                    "push 0x642e3233;",
                    "push 0x5f327377;",
                ]
            ),
        )


if __name__ == "__main__":
    unittest.main()
