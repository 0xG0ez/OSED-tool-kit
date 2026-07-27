def _contains_bad_bytes(value: int, size: int, bad_bytes: set[int]) -> bool:
    """Return True when any byte in the little-endian immediate is forbidden."""
    return any(byte in bad_bytes for byte in value.to_bytes(size, "little"))


def _format_word(chunk: bytes) -> str:
    """Format a 2-byte chunk as a little-endian x86 word immediate."""
    return f"0x{int.from_bytes(chunk, 'little'):04x}"


def _format_dword(chunk: bytes) -> str:
    """Format a 4-byte chunk as a little-endian x86 dword immediate."""
    return f"0x{int.from_bytes(chunk, 'little'):08x}"


def _neg_push(value: int, clean_reg: str, bad_bytes: set[int]) -> list[str] | None:
    """Encode a dword via two's-complement negation when direct bytes are bad."""
    negated = (-value) & 0xFFFFFFFF
    if _contains_bad_bytes(negated, 4, bad_bytes):
        return None

    return [
        f"mov {clean_reg}, 0x{negated:08x};",
        f"neg {clean_reg};",
        f"push {clean_reg};",
    ]


def _push_partial_tail(
    chunk: bytes, clean_reg: str, reg_is_zero: bool, bad_bytes: set[int]
) -> list[str]:
    """Push a 1-3 byte tail while preserving a null-terminated C string layout."""
    instructions = []
    if not reg_is_zero:
        instructions.append(f"xor {clean_reg}, {clean_reg};")

    if len(chunk) == 1:
        instructions.append(f"mov {clean_reg[1]}l, 0x{chunk[0]:02x};")
    elif len(chunk) == 2:
        instructions.append(f"mov {clean_reg[1]}x, {_format_word(chunk)};")
    elif len(chunk) == 3:
        value = int.from_bytes(chunk + b"\x00", "little")
        neg_push = _neg_push(value, clean_reg, bad_bytes)
        if neg_push:
            return neg_push

        instructions.extend(
            [
                f"mov {clean_reg[1]}l, 0x{chunk[2]:02x};",
                f"shl {clean_reg}, 0x10;",
                f"mov {clean_reg[1]}x, {_format_word(chunk[:2])};",
            ]
        )
    else:
        raise ValueError("partial chunk must be 1 to 3 bytes")

    instructions.append(f"push {clean_reg};")
    return instructions


def _push_dword(chunk: bytes, clean_reg: str, bad_bytes: set[int]) -> list[str]:
    """Push a 4-byte chunk directly or via negation if the immediate is dirty."""
    value = int.from_bytes(chunk, "little")
    if not _contains_bad_bytes(value, 4, bad_bytes):
        return [f"push {_format_dword(chunk)};"]

    neg_push = _neg_push(value, clean_reg, bad_bytes)
    if neg_push:
        return neg_push

    raise ValueError(f"cannot encode {chunk!r} without bad immediate bytes")


def push_string(
    input_string: str,
    clean_reg: str = "eax",
    target_reg: str | None = None,
    init_null: bool = True,
    bad_bytes: set[int] | None = None,
) -> str:
    """Return x86 push instructions for a null-terminated stack string.

    The string is emitted from right to left in dword-sized pushes. Uneven
    tails are built in a zeroed register so the final in-memory layout ends in
    a real null terminator instead of filler bytes. When a direct immediate
    contains forbidden bytes, the helper falls back to a negation-based form.
    """
    bad_bytes = {0x00} if bad_bytes is None else set(bad_bytes)
    data = input_string.encode("latin-1")
    if not data:
        raise ValueError("input_string must not be empty")
    if any(byte == 0x00 for byte in data):
        raise ValueError("input_string must not contain embedded null bytes")
    if clean_reg not in {"eax", "ebx", "ecx", "edx"}:
        raise ValueError("clean_reg must be eax, ebx, ecx, or edx")

    instructions = []
    tail_len = len(data) % 4
    reg_is_zero = False
    if init_null and tail_len == 0:
        instructions.append(f"xor {clean_reg}, {clean_reg}                    ;")
        instructions.append(f"push {clean_reg}                        ;")
        reg_is_zero = True

    if tail_len:
        instructions.extend(
            _push_partial_tail(
                data[-tail_len:], clean_reg, reg_is_zero, bad_bytes
            )
        )
        data = data[:-tail_len]
        reg_is_zero = False

    for offset in range(len(data) - 4, -1, -4):
        instructions.extend(
            _push_dword(data[offset : offset + 4], clean_reg, bad_bytes)
        )

    if target_reg:
        instructions.append("push esp                        ;")
        instructions.append(f"pop {target_reg}                         ;")

    return "\n".join(instructions)
