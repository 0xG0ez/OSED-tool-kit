# OSED Exploit Development Toolkit

A comprehensive collection of specialized tools designed for the research, development, and debugging of Windows x86 exploit payloads. This toolkit was specifically engineered to overcome common challenges in binary exploitation, such as restricted character sets, null-byte avoidance, and complex memory constraints.

## 🛠 Main Tools Overview

### 1. Kasm Shell (`kasm_shell.py`)
An interactive assembly environment powered by the **Keystone** and **Capstone** engines. It allows for real-time assembly with a focus on **Bad Character Evasion**.
* **Polymorphic Engine**: Automatically suggests logical equivalents (e.g., `xor eax, eax` for `mov eax, 0`) to avoid forbidden bytes.
* **Stack String Utility**: Generates null-free `PUSH` sequences for any given string, handling 4-byte alignment and little-endian ordering for the Windows stack.
* **Live Disassembly**: Instantly analyzes hex strings to identify which specific bytes trigger bad character alerts.

### 2. Shellcoder Engine (`shellcoder-v2.py`)
The primary compilation engine for complex Windows payloads. 
* **Credits**: This tool is based on the original work and design by **epi** and **Kavanyy**, specifically adapted and expanded for OSED-level research and Windows x86 exploitation.
* **ShellcodeHelper Abstraction**: Payload builders now share a dedicated helper class in [`shellcode/shellcode_helper.py`](shellcode/shellcode_helper.py) that handles stack-slot allocation, writable structure buffers, function-hash resolution, DLL loading, and common resolver bootstrap assembly.
* **Cleaner Payload Modules**: Reverse shell, bind shell, MSI stager, and message box payloads live as separate modules under [`shellcode/`](shellcode/) instead of being inlined into one large file.
* **Safer Stack Layouts**: Centralized buffer reservation and offset validation reduce mistakes when writing `STARTUPINFOA`, `sockaddr_in`, and other stack-backed structures.
* **Consistent String Handling**: Shared helpers build null-terminated strings and writable command buffers without ad hoc padding or duplicate string-push logic.
* **Automated XOR Encoder**: Iteratively searches for a clean 4-byte XOR key to bypass filters when static payloads contain bad characters, automatically prepending the necessary decoder stub.
* **WinAPI Hashing**: Utilizes ror-13 hashing for function resolution (e.g., LoadLibraryA, CreateProcessA, WSAStartup) to keep payloads compact and robust against different Windows versions.
* **Modular Templates**: Pre-built logic for reverse shells, bind shells, MSI exec stagers, and message box payloads. Writing custom shellcode is much easier because the shared helper handles the resolver/bootstrap boilerplate and keeps function pointers, buffers, and stack-backed variables organized so you do not have to manually track where everything lives.

### 3. Egghunter Generator (`egghunter.py`)
A modular tool to generate optimized egghunter payloads for Windows x86.
* Supports both **Classic Syscall (0x2e)** for Windows XP/7/10 and **SEH-based** variants for bypass scenarios.
* Includes a `--negate` option to ensure the syscall ID does not contain forbidden null bytes in the shellcode.

### 4. Pattern Tool (`patternTool.py`)
A flexible utility for calculating exact memory offsets during application crashes.
* Supports custom charsets (upper, lower, digit, symbol) to adapt to specific input filters.
* Capable of generating and searching patterns up to 700,000+ bytes without repetition.

### 5. Shellcode Checker (`shellChecker.py`)
A critical debugging aid for payload verification in a lab environment.
* Compares generated shellcode against a **WinDbg memory dump** (`db` command output) to pinpoint exactly where a payload is being truncated, corrupted, or modified by the application's memory manager.

### 6. Badchar Generator (`badchar_gen.py`)
Automates the creation of byte arrays for bad character discovery.
* Supports multiple output formats (Python, C, Raw).
* Allows segmented splitting to identify bad chars in smaller chunks when large buffer space is unavailable.

## Installation

These tools require Python 3 and several specialized libraries. Install the dependencies using pip:

```bash
pip install keystone-engine colorama
```

Capstone is optional for `shellcoder-v2.py`. Install it to get instruction-level bad-character analysis instead of raw byte-offset reporting:

```bash
pip install capstone
```
