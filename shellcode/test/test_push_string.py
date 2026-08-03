import unittest

from shellcode.push_string import NegativeAdd, push_string


class PushStringTests(unittest.TestCase):
    def test_negative_add_returns_bad_byte_free_assembly(self):
        encoder = NegativeAdd(0x41414141, {0x00, 0x41, 0xBE, 0xBF}, max_count=4)

        self.assertEqual(
            encoder.asm("ecx"),
            "\n".join(
                [
                    "xor ecx, ecx;",
                    "add ecx, 0x80010101;",
                    "add ecx, 0xc1404040;",
                    "push ecx;",
                ]
            ),
        )

    def test_push_string_uses_negative_add_when_other_dword_encodings_are_dirty(self):
        self.assertEqual(
            push_string("AAAA", bad_bytes={0x00, 0x41, 0xBE, 0xBF}),
            "\n".join(
                [
                    "xor eax, eax                    ;",
                    "push eax                        ;",
                    "xor eax, eax;",
                    "add eax, 0x80010101;",
                    "add eax, 0xc1404040;",
                    "push eax;",
                ]
            ),
        )

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
