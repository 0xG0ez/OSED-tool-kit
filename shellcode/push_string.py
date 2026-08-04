MASK = 0xFFFFFFFF


class NegativeAdd:
    """Build a bad-byte-free register value using signed-negative addends.

    Each addend has its most-significant byte set, so it is negative when
    interpreted as a signed 32-bit integer.  The encoded immediate is still
    the unsigned 32-bit value, which lets callers use the result directly in
    shellcode without forbidden immediate bytes.
    """

    def __init__(
        self,
        target: int,
        bad_bytes: set[int] | None = None,
        max_count: int = 16,
    ) -> None:
        if not isinstance(target, int):
            raise TypeError("target must be an integer")
        if not isinstance(max_count, int) or max_count < 1:
            raise ValueError("max_count must be a positive integer")

        self.target = target & MASK
        self.bad_bytes = {0x00} if bad_bytes is None else set(bad_bytes)
        if any(not isinstance(byte, int) or not 0 <= byte <= 0xFF
               for byte in self.bad_bytes):
            raise ValueError("bad_bytes must contain byte values")
        self.max_count = max_count

    @staticmethod
    def _byte_sums(count: int, allowed: list[int]) -> dict[int, tuple[int, ...]]:
        sums: dict[int, tuple[int, ...]] = {0: ()}
        for _ in range(count):
            next_sums: dict[int, tuple[int, ...]] = {}
            for total, values in sums.items():
                for value in allowed:
                    next_sums.setdefault(total + value, values + (value,))
            sums = next_sums
        return sums

    def addends(self) -> list[int] | None:
        """Return encoded dword addends, or ``None`` when no solution exists."""
        allowed = [value for value in range(256) if value not in self.bad_bytes]
        negative_msb = [value for value in allowed if value >= 0x80]
        if not negative_msb:
            return None

        target_bytes = self.target.to_bytes(4, "little")
        for count in range(1, self.max_count + 1):
            normal_sums = self._byte_sums(count, allowed)
            msb_sums = self._byte_sums(count, negative_msb)
            states: dict[int, list[tuple[int, ...]]] = {0: []}

            for index, target_byte in enumerate(target_bytes):
                sums = msb_sums if index == 3 else normal_sums
                next_states: dict[int, list[tuple[int, ...]]] = {}
                for carry, columns in states.items():
                    for total, values in sums.items():
                        column_total = total + carry
                        if column_total & 0xFF == target_byte:
                            next_states.setdefault(
                                column_total >> 8, columns + [values]
                            )
                states = next_states
                if not states:
                    break

            if states:
                columns = next(iter(states.values()))
                return [
                    sum(columns[byte][item] << (8 * byte) for byte in range(4))
                    for item in range(count)
                ]
        return None

    def instructions(self, register: str = "eax") -> list[str]:
        """Return assembly instructions that calculate and push the target."""
        addends = self.addends()
        if addends is None:
            raise ValueError(
                f"cannot encode 0x{self.target:08x} without bad bytes"
            )
        return [
            f"xor {register}, {register};",
            *(f"add {register}, 0x{addend:08x};" for addend in addends),
            f"push {register};",
        ]

    def asm(self, register: str = "eax") -> str:
        """Return newline-separated assembly suitable for shellcode builders."""
        return "\n".join(self.instructions(register))


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


def push_dword(chunk: bytes | int, clean_reg: str, bad_bytes: set[int]) -> list[str]:
    """Push a dword directly or via negation if the immediate is dirty.

    ``chunk`` may be either four bytes in little-endian order or an unsigned
    32-bit integer.
    """
    if isinstance(chunk, int):
        if not 0 <= chunk <= MASK:
            raise ValueError("dword integer must be between 0 and 0xffffffff")
        value = chunk
    elif not isinstance(chunk, bytes):
        raise TypeError("chunk must be bytes or an integer")
    else:
        value = int.from_bytes(chunk, "little")

    if not _contains_bad_bytes(value, 4, bad_bytes):
        return [f"push 0x{value:08x};"]

    neg_push = _neg_push(value, clean_reg, bad_bytes)
    if neg_push:
        return neg_push

    additive_push = NegativeAdd(value, bad_bytes=bad_bytes).instructions(clean_reg)
    if additive_push:
        return additive_push

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
            push_dword(data[offset : offset + 4], clean_reg, bad_bytes)
        )

    if target_reg:
        instructions.append("push esp                        ;")
        instructions.append(f"pop {target_reg}                         ;")

    return "\n".join(instructions)
