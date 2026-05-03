from __future__ import annotations

SYMBOL_CAPABILITY_MAP = {
    "connect": "network",
    "socket": "network",
    "send": "network",
    "recv": "network",
    "getaddrinfo": "network",
    "open": "file_read",
    "openat": "file_read",
    "fopen": "file_read",
    "read": "file_read",
    "write": "file_write",
    "pwrite": "file_write",
    "fwrite": "file_write",
    "unlink": "file_write",
    "rename": "file_write",
    "system": "process_spawn",
    "execve": "process_spawn",
    "fork": "process_spawn",
    "posix_spawn": "process_spawn",
    "dlopen": "dynamic_loading",
    "dlsym": "dynamic_loading",
    "getenv": "environment_access",
    "ptrace": "anti_debug",
}


def capability_for_symbol(symbol: str) -> str | None:
    return SYMBOL_CAPABILITY_MAP.get(symbol)
