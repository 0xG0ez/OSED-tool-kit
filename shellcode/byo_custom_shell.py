"""Bring-your-own-shellcode example for ``shellcoder-v2.py --custom``.

This wrapper demonstrates the custom-module contract while reusing the
educational bind-shell builder as a starting point for further changes.
"""

from shellcode.payload_utils import (
  flatten_asm,
  format_shellcode_asm,
)
from shellcode.shellcode_helper import ShellcodeHelper

def shellcode(lhost, lport, breakpoint=0, bad_bytes=None):
  """Return bind-shell assembly using the standard custom-module signature.

  """
  var = ShellcodeHelper(bad_bytes=bad_bytes)

  # Add functions
  f_term_process = "TerminateProcess" # kernel32.dll

  for function_name in (
        f_term_process,
    ):
        var.add(function_name)

  # Add variables as needed
  v_some_buffer = "named_buffer"
  var.add(v_some_buffer, reserve=0x80) # create an 0x80 byte variable on the stack

  asm = [
    "start:",
    f"{['', 'int3;'][breakpoint]}"         ,
    var.get_esp_setup()                    , # reserve scratch space for variables and temporary structures
    var.get_clear_variables()              , # zero the stack-backed variable area
    var.get_common_shellcode()             , # locate kernel32 and bootstrap resolver helpers

    # Directly after the common shellcode, the find function routine will look in kernel32.dll until the
    # next library is loaded
    "   resolve_symbols_kernel32:         ",
    var.find_function(f_term_process)      ,
    "   exec_shellcode:                   ",  # terminate the original thread/process context after the child is created
        "       xor ecx, ecx             ;",
        "       push ecx                 ;",
        "       push 0xffffffff          ;",
        var.call_function(f_term_process),
  ]
  return format_shellcode_asm("\n".join(flatten_asm(asm)))
