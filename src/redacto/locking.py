"""Reentrant process/thread locks for cooperating local writers.

Locks live beside the configured resource and survive atomic file replacement.
OS locks are released on process death. Direct writers that ignore this protocol
remain outside its guarantee; rescans must detect their changes.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from redacto.adapters.base import AdapterError

_registry_guard = threading.Lock()
_registry: dict[str, threading.RLock] = {}
_held = threading.local()


def is_lock_file(path: Path) -> bool:
    """Recognize an empty coordination sidecar, never a stored context record."""
    if not re.fullmatch(r"\.redacto-lock-[0-9a-f]{24}", path.name):
        return False
    try:
        return path.is_file() and path.read_bytes() in {b"\0", b"\0\0"}
    except OSError:
        return False


@contextmanager
def resource_lock(resource: Path, *, timeout: float = 30.0):
    resource = Path(resource).resolve()
    identity = os.path.normcase(str(resource))
    digest = hashlib.sha256(identity.encode()).hexdigest()[:24]
    lock_path = resource.parent / f".redacto-lock-{digest}"
    with _registry_guard:
        thread_lock = _registry.setdefault(identity, threading.RLock())
    if not thread_lock.acquire(timeout=timeout):
        raise AdapterError("resource is busy", code="store_busy", retryable=True)
    try:
        held = getattr(_held, "resources", None)
        if held is None:
            held = _held.resources = set()
        if identity in held:
            yield
            return
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            # msvcrt locks a byte range, even on an otherwise empty sidecar.
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AdapterError("resource is busy", code="store_busy", retryable=True)
                    time.sleep(0.01)
            held.add(identity)
            try:
                yield
            finally:
                held.remove(identity)
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        thread_lock.release()


def locked_store(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        resource = getattr(self, "_path", None) or self._root
        with resource_lock(resource):
            return method(self, *args, **kwargs)

    return wrapped


def coordinated(method):
    """Serialize application reads/writes and revocation on one graph database."""
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with resource_lock(self.settings.db_path):
            return method(self, *args, **kwargs)

    return wrapped
