"""Cross-platform process liveness.

`os.kill(pid, 0)` is not a liveness probe on Windows: signal 0 maps to
`TerminateProcess`, so it can kill the process (or, in pytest, interrupt the test
run). This module uses `OpenProcess` + `GetExitCodeProcess` on Windows and
`os.kill(pid, 0)` on POSIX.
"""

from __future__ import annotations

import os
import sys

_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_INVALID_PARAMETER = 87
_ERROR_ACCESS_DENIED = 5


def pid_alive(pid: int) -> bool:
    """Return True when a process with this PID exists.

    Returns True when liveness cannot be determined (access denied), so callers
    fail safe: an unverifiable owner is treated as possibly alive.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if sys.platform == "win32":
        return _pid_alive_windows(pid)
    return _pid_alive_posix(pid)


def _pid_alive_posix(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _pid_alive_windows(pid: int) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error == _ERROR_INVALID_PARAMETER:
            return False
        if error == _ERROR_ACCESS_DENIED:
            return True
        return True
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)