import unittest
from contextlib import redirect_stdout
from io import StringIO

from shellcode.shellcode_helper import ShellcodeHelper


class ShellcodeHelperTests(unittest.TestCase):
    def test_allocates_four_byte_slots(self):
        variables = ShellcodeHelper()

        self.assertEqual(variables.add("terminate_process"), 16)
        self.assertEqual(variables.add("load_ws2_32"), 20)
        self.assertEqual(
            variables.items(),
            (
                ("find_function", 4),
                ("common_temp", 8),
                ("LoadLibraryA", 12),
                ("terminate_process", 16),
                ("load_ws2_32", 20),
            ),
        )

    def test_emits_commands(self):
        variables = ShellcodeHelper()

        self.assertEqual(variables.write_var("find_function"), "mov [ebp-0x04], eax ;")
        self.assertEqual(variables.read_var("find_function"), "mov eax, [ebp-0x04] ;")
        self.assertEqual(
            variables.write_var("find_function", reg_src="ecx"),
            "mov [ebp-0x04], ecx ;",
        )
        self.assertEqual(
            variables.read_var("find_function", reg_dst="edi"),
            "mov edi, [ebp-0x04] ;",
        )
        self.assertEqual(
            variables.get_var_address("find_function"),
            "lea eax, [ebp-0x04]",
        )
        self.assertEqual(
            variables.get_var_address("find_function", reg_dst="esi"),
            "lea esi, [ebp-0x04]",
        )
        self.assertEqual(
            variables.call_function("find_function"),
            "call dword ptr [ebp-0x04] ;",
        )
        self.assertEqual(
            variables._get_lowest_address(),
            "lea eax, [ebp-0x0c]",
        )

    def test_supports_configuration(self):
        variables = ShellcodeHelper(start_offset=0x10, step=8, base_register="esp")
        variables.add("value")

        self.assertEqual(variables._offset("value"), 0x28)
        self.assertEqual(variables.write_var("value"), "mov [esp-0x28], eax ;")

    def test_reserves_space_after_variable(self):
        variables = ShellcodeHelper()

        self.assertEqual(variables.add("buffer", reserve=0x20), 0x10)
        self.assertEqual(variables.add("next"), 0x30)
        self.assertEqual(variables._offset("buffer"), 0x10)
        self.assertEqual(
            variables.write_var("buffer"),
            "mov [ebp-0x2c], eax ;",
        )
        self.assertEqual(
            variables.read_var("buffer"),
            "mov eax, [ebp-0x2c] ;",
        )
        self.assertEqual(
            variables.push_var_value("buffer"),
            [
                "mov eax, [ebp-0x2c] ;",
                "push eax;",
            ],
        )
        self.assertEqual(
            variables.get_var_address("buffer"),
            "lea eax, [ebp-0x2c]",
        )
        self.assertEqual(
            variables.get_var_address("next"),
            "lea eax, [ebp-0x30]",
        )
        self.assertEqual(
            variables._get_lowest_address(),
            "lea eax, [ebp-0x30]",
        )
        self.assertEqual(
            variables._get_lowest_address("edi"),
            "lea edi, [ebp-0x30]",
        )

    def test_writes_reserved_structure_fields_from_lowest_memory(self):
        variables = ShellcodeHelper()
        variables.add("startup_info", reserve=0x44)

        self.assertEqual(
            variables.set_variable_with_offset("startup_info", 0x38, "esi"),
            ["mov [ebp-0x18], esi ;"],
        )
        self.assertEqual(
            variables.write_var("startup_info", offset=0x38),
            "mov [ebp-0x18], eax ;",
        )
        with self.assertRaises(ValueError):
            variables.set_variable_with_offset("startup_info", 0x44, "esi")
        with self.assertRaises(ValueError):
            variables.write_var("startup_info", offset=0x44)

    def test_set_variable_data_does_not_increment_after_last_byte(self):
        variables = ShellcodeHelper()
        variables.add("buffer", reserve=0x04)

        self.assertEqual(
            variables.set_variable_data("buffer", b"AB"),
            [
                "lea edi, [ebp-0x10]",
                "mov byte ptr[edi], 0x41;",
                "inc edi;",
                "mov byte ptr[edi], 0x42;",
            ],
        )

    def test_set_variable_data_rejects_writes_past_reserved_buffer(self):
        variables = ShellcodeHelper()
        variables.add("buffer", reserve=0x04)

        with self.assertRaises(ValueError):
            variables.set_variable_data("buffer", b"ABCDE")

    def test_set_variable_data_rejects_non_byte_values(self):
        variables = ShellcodeHelper()
        variables.add("buffer", reserve=0x04)

        with self.assertRaises(ValueError):
            variables.set_variable_data("buffer", [0x100])

    def test_reports_variables_and_total_reserved_space(self):
        variables = ShellcodeHelper()
        variables.add("buffer", reserve=0x20)
        variables.add("next")

        output = StringIO()
        with redirect_stdout(output):
            variables.print_variables()

        self.assertEqual(
            output.getvalue(),
            "; variable allocations:\n"
            "; name           address          reserved\n"
            "; next           [ebp-0x30]  0x04 bytes\n"
            "; buffer         [ebp-0x2c]  0x20 bytes\n"
            "; LoadLibraryA   [ebp-0x0c]  0x04 bytes\n"
            "; common_temp    [ebp-0x08]  0x04 bytes\n"
            "; find_function  [ebp-0x04]  0x04 bytes\n",
        )
        self.assertEqual(variables._total_bytes_reserved(), 0x30)

    def test_total_reserved_space_includes_mandatory_variables(self):
        self.assertEqual(ShellcodeHelper()._total_bytes_reserved(), 0x0c)

    def test__get_lowest_address_defaults_to_highest_mandatory_variable(self):
        self.assertEqual(ShellcodeHelper()._get_lowest_address(), "lea eax, [ebp-0x0c]")

    def test_rejects_invalid_reservation(self):
        variables = ShellcodeHelper()

        with self.assertRaises(ValueError):
            variables.add("buffer", reserve=-1)
        with self.assertRaises(ValueError):
            variables.add("buffer", reserve=1.5)
        with self.assertRaises(ValueError):
            variables.add("buffer", reserve=1)
        with self.assertRaises(ValueError):
            variables.add("buffer", reserve=6)

    def test_rejects_invalid_or_duplicate_names(self):
        variables = ShellcodeHelper()

        with self.assertRaises(ValueError):
            variables.add("not valid")
        variables.add("value")
        with self.assertRaises(ValueError):
            variables.add("value")
        with self.assertRaises(KeyError):
            variables.write_var("missing")
        with self.assertRaises(KeyError):
            variables.read_var("missing")

        with self.assertRaises(ValueError):
            variables.write_var("value", reg_src="eax]")
        with self.assertRaises(ValueError):
            variables.read_var("value", reg_dst=" eax")
        with self.assertRaises(ValueError):
            variables.get_var_address("value", reg_dst="eax]")

    def test_rejects_invalid_configuration(self):
        with self.assertRaises(ValueError):
            ShellcodeHelper(start_offset=0)
        with self.assertRaises(ValueError):
            ShellcodeHelper(step=-4)
        with self.assertRaises(ValueError):
            ShellcodeHelper(base_register="ebp]")

    def test_selects_hash_rotation_that_avoids_bad_bytes(self):
        cases = (
            (set(), "ror edx, 0xd;", 0xB3C091A2),
            ({0x0D}, "rol edx, 0x13;", 0xB3C091A2),
            ({0x0D, 0x13}, "ror edx, 0xb;", 0xCF02468A),
            ({0x0D, 0x13, 0x0B}, "rol edx, 0x15;", 0xCF02468A),
        )

        for bad_bytes, expected_instruction, expected_rotation in cases:
            with self.subTest(bad_bytes=bad_bytes):
                variables = ShellcodeHelper(bad_bytes=bad_bytes)

                self.assertEqual(
                    variables._rotate_str(0x12345678),
                    expected_rotation,
                )
                self.assertIn(expected_instruction, variables.get_common_shellcode())

    def test_hash_push_uses_selected_rotation(self):
        self.assertEqual(
            ShellcodeHelper().push_function_hash("ExitProcess"),
            ["push 0x73e2d87e;"],
        )
        self.assertEqual(
            ShellcodeHelper(bad_bytes={0x0D, 0x13}).push_function_hash(
                "ExitProcess"
            ),
            ["push 0x9a06e1c7;"],
        )


if __name__ == "__main__":
    unittest.main()
