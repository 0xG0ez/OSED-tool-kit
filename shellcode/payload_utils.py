"""Shared helpers for shellcode payload builder modules."""

from __future__ import annotations

import ipaddress


def to_network_endpoint_bytes(ip_address, port):
    """Return IPv4 and big-endian port bytes for a sockaddr_in payload."""
    ip_bytes = ipaddress.IPv4Address(ip_address).packed

    port_int = int(port)
    if not 0 <= port_int <= 0xFFFF:
        raise ValueError("port must be in range 0-65535")

    port_bytes = port_int.to_bytes(2, "big")
    return ip_bytes, port_bytes


def format_shellcode_asm(assembly: str) -> str:
    """Align shellcode labels, instructions, and comments for readability."""
    formatted = []
    for source_line in assembly.splitlines():
        line = source_line.strip()
        if not line:
            continue

        if line.endswith(":"):
            formatted.append(line)
            continue

        instruction, separator, comment = line.partition(";")
        instruction = instruction.strip()
        if separator:
            formatted.append(f"    {instruction:<36} ; {comment.strip()}")
        else:
            formatted.append(f"    {instruction}")

    return "\n".join(formatted)


def flatten_asm(items):
    """Flatten nested lists of assembly strings into a single list."""
    flattened = []
    for item in items:
        if isinstance(item, list):
            flattened.extend(flatten_asm(item))
        else:
            flattened.append(item)
    return flattened
