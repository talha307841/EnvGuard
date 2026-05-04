"""
Background service / daemon logic for EnvGuard.

Provides start/stop/status helpers that manage a PID file under ~/.envguard/.
Works on macOS, Linux, and Windows (without requiring root).
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path

from envguard.config import PID_PATH, get_log_path, load_config, resolve_watched_dirs
from envguard.watcher import EnvFileEventHandler, run_watcher

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(str(log_path.parent / "envguard_service.log"), encoding="utf-8"),
        ],
    )


# ---------------------------------------------------------------------------
# PID helpers
# ---------------------------------------------------------------------------

def _write_pid(pid: int) -> None:
    PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    PID_PATH.write_text(str(pid), encoding="utf-8")


def _read_pid() -> int | None:
    if not PID_PATH.exists():
        return None
    try:
        return int(PID_PATH.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _remove_pid() -> None:
    try:
        PID_PATH.unlink(missing_ok=True)
    except OSError:
        pass


def _process_is_running(pid: int) -> bool:
    """Return True if a process with the given PID exists."""
    try:
        if sys.platform == "win32":
            import ctypes
            SYNCHRONIZE = 0x00100000
            handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)  # type: ignore[attr-defined]
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


# ---------------------------------------------------------------------------
# Daemon entry point (runs inside the spawned process)
# ---------------------------------------------------------------------------

def _daemon_main() -> None:
    """Main loop executed inside the daemon process."""
    config = load_config()
    log_path = get_log_path(config)
    _setup_logging(log_path)

    watched_dirs = resolve_watched_dirs(config)
    safe_keys = set(config.get("safe_keys", []))
    mask_char = config.get("mask_char", "*")
    keep_prefix_chars = int(config.get("keep_prefix_chars", 3))

    handler = EnvFileEventHandler(
        log_path=log_path,
        safe_keys=safe_keys,
        mask_char=mask_char,
        keep_prefix_chars=keep_prefix_chars,
    )

    logger.info("EnvGuard daemon started (pid=%d)", os.getpid())
    run_watcher(watched_dirs, handler)
    logger.info("EnvGuard daemon stopped")
    _remove_pid()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_daemon() -> tuple[bool, str]:
    """
    Start the EnvGuard daemon in a background process.

    Returns (success, message).
    """
    existing_pid = _read_pid()
    if existing_pid and _process_is_running(existing_pid):
        return False, f"EnvGuard is already running (pid={existing_pid})"

    if sys.platform == "win32":
        return _start_daemon_windows()
    else:
        return _start_daemon_unix()


def _start_daemon_unix() -> tuple[bool, str]:
    """Fork a daemon process on Unix/macOS."""
    try:
        pid = os.fork()  # type: ignore[attr-defined]
    except AttributeError:
        # os.fork not available (shouldn't happen on Unix, but be safe)
        return _start_daemon_subprocess()

    if pid > 0:
        # Parent: write PID file and return
        _write_pid(pid)
        return True, f"EnvGuard started (pid={pid})"

    # Child: become a daemon
    try:
        os.setsid()  # type: ignore[attr-defined]
        # Redirect stdin/stdout/stderr to /dev/null
        devnull = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            try:
                os.dup2(devnull, fd)
            except OSError:
                pass
        os.close(devnull)
        _daemon_main()
    except Exception as exc:  # noqa: BLE001
        # Log to stderr before redirect takes effect
        print(f"EnvGuard daemon error: {exc}", file=sys.stderr)
    finally:
        os._exit(0)

    return True, ""  # unreachable


def _start_daemon_subprocess() -> tuple[bool, str]:
    """Start daemon as a detached subprocess (fallback)."""
    import subprocess

    cmd = [sys.executable, "-m", "envguard._daemon_runner"]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    _write_pid(proc.pid)
    return True, f"EnvGuard started (pid={proc.pid})"


def _start_daemon_windows() -> tuple[bool, str]:
    """Start daemon as a detached process on Windows."""
    import subprocess

    CREATE_NEW_PROCESS_GROUP = 0x00000200
    DETACHED_PROCESS = 0x00000008

    cmd = [sys.executable, "-m", "envguard._daemon_runner"]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
    )
    _write_pid(proc.pid)
    return True, f"EnvGuard started (pid={proc.pid})"


def stop_daemon() -> tuple[bool, str]:
    """Stop the running EnvGuard daemon. Returns (success, message)."""
    pid = _read_pid()
    if pid is None:
        return False, "EnvGuard is not running (no PID file found)"

    if not _process_is_running(pid):
        _remove_pid()
        return False, f"EnvGuard process (pid={pid}) is not running; removed stale PID file"

    try:
        if sys.platform == "win32":
            import ctypes
            PROCESS_TERMINATE = 0x0001
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)  # type: ignore[attr-defined]
            if handle:
                ctypes.windll.kernel32.TerminateProcess(handle, 0)  # type: ignore[attr-defined]
                ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
        else:
            os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError) as exc:
        return False, f"Failed to stop EnvGuard (pid={pid}): {exc}"

    _remove_pid()
    return True, f"EnvGuard stopped (pid={pid})"


def get_status() -> dict:
    """Return a status dict with running state, pid, and watched dirs."""
    pid = _read_pid()
    running = pid is not None and _process_is_running(pid)
    config = load_config()
    return {
        "running": running,
        "pid": pid if running else None,
        "watched_dirs": config.get("watched_dirs", []),
        "log_file": config.get("log_file", ""),
    }


def get_log_lines(n: int | None = None) -> list[str]:
    """Return the last n lines from the access log (or all if n is None)."""
    config = load_config()
    log_path = get_log_path(config)
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").splitlines()
    if n is not None:
        return lines[-n:]
    return lines
