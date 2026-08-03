"""MessageBox payload builder."""

from shellcode.payload_utils import flatten_asm, format_shellcode_asm
from shellcode.shellcode_helper import ShellcodeHelper


def msg_box(header, text, breakpoint=0, bad_bytes=None):
    var = ShellcodeHelper(bad_bytes=bad_bytes)

    f_term_process = "TerminateProcess"
    f_msgbox = "MessageBoxA"

    for function_name in (f_term_process, f_msgbox):
        var.add(function_name)

    v_header = "msgbox_header"
    v_text = "msgbox_text"

    var.add(v_header, reserve=max(0x10, var.align_dword(len(header) + 1)))
    var.add(v_text, reserve=max(0x10, var.align_dword(len(text) + 1)))

    asm = [
        "start:",
        f"{['', 'int3;'][breakpoint]}",
        var.get_esp_setup(),                    # reserve scratch space for resolver state and message buffers
        var.get_clear_variables(),              # zero the stack-backed variable area
        var.get_common_shellcode(),             # locate kernel32 and bootstrap find_function/LoadLibraryA

        "   resolve_symbols_kernel32: ",        # resolve the APIs needed before loading user32
        var.find_function(f_term_process),

        "   load_user32:                         ",  # load user32.dll so MessageBoxA can be resolved
        var.load_library("user32.dll"),

        "   resolve_symbols_user32:              ",  # resolve MessageBoxA from the loaded module
        var.find_function(f_msgbox),

        "   create_header_string:                ",  # build the message-box caption in writable memory
        var.set_variable_data(v_header, header),
        "   create_text_string:                  ",  # build the message-box body in writable memory
        var.set_variable_data(v_text, text),

        "   call_messageboxa:                    ",  # MessageBoxA(NULL, text, header, MB_OK)
        "       xor eax, eax                    ;",
        "       push eax                        ;",
        var.push_var_address(v_header, "ebx"),
        var.push_var_address(v_text, "ebx"),
        "       push eax                        ;",
        var.call_function(f_msgbox),

        "   exec_shellcode:                      ",  # terminate once the dialog is dismissed
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        var.call_function(f_term_process),
    ]
    return format_shellcode_asm("\n".join(flatten_asm(asm)))
