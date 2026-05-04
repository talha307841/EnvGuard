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
import time
import traceback
from pathlib import Path
from typing import Optional

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


def _write_startup_crash(exc: Exception) -> None:
    """Persist daemon startup crashes so failures are diagnosable."""
    PID_PATH.parent.mkdir(parents=True, exist_ok=True)
    crash_log = PID_PATH.parent / "daemon_crash.log"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    detail = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    with crash_log.open("a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] Daemon startup failure\n{detail}\n")


def _startup_state_path(pid: int) -> Path:
    return PID_PATH.parent / f"startup.{pid}.state"


def _write_startup_state(path: Optional[Path], state: str, detail: str = "") -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = state if not detail else f"{state}:{detail}"
    path.write_text(payload, encoding="utf-8")


def _read_startup_state(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _clear_startup_state(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _wait_for_startup(pid: int, timeout_seconds: float = 3.0) -> tuple[bool, str]:
    """Wait for daemon startup handshake (ready/error) or early exit."""
    state_path = _startup_state_path(pid)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        state = _read_startup_state(state_path)
        if state.startswith("ready"):
            _clear_startup_state(state_path)
            return True, f"EnvGuard started (pid={pid})"
        if state.startswith("error"):
            _clear_startup_state(state_path)
            crash_log = PID_PATH.parent / "daemon_crash.log"
            if crash_log.exists():
                return False, f"EnvGuard failed to start; see {crash_log}"
            return False, "EnvGuard failed to start (watcher initialization error)"

        # Reap exited child promptly on Unix fork path; ignore where unsupported.
        if os.name == "posix":
            try:
                waited_pid, _ = os.waitpid(pid, os.WNOHANG)
            except OSError:
                waited_pid = 0
            if waited_pid == pid:
                _clear_startup_state(state_path)
                crash_log = PID_PATH.parent / "daemon_crash.log"
                if crash_log.exists():
                    return False, f"EnvGuard failed to start; see {crash_log}"
                return False, "EnvGuard failed to start (process exited immediately)"

        if not _process_is_running(pid):
            _clear_startup_state(state_path)
            crash_log = PID_PATH.parent / "daemon_crash.log"
            if crash_log.exists():
                return False, f"EnvGuard failed to start; see {crash_log}"
            return False, "EnvGuard failed to start (process exited immediately)"

        time.sleep(0.05)

    _clear_startup_state(state_path)
    if _process_is_running(pid):
        return True, f"EnvGuard started (pid={pid})"
    crash_log = PID_PATH.parent / "daemon_crash.log"
    if crash_log.exists():
        return False, f"EnvGuard failed to start; see {crash_log}"
    return False, "EnvGuard failed to start (startup timeout)"


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
            # Prefer psutil so zombie processes are not treated as healthy.
            import psutil  # type: ignore

            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_ZOMBIE:
                return False
            return proc.is_running()
    except (ProcessLookupError, PermissionError, OSError):
        return False
    except Exception:
        # Fallback if psutil fails unexpectedly on a platform edge-case.
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError, OSError):
            return False


# ---------------------------------------------------------------------------
# Daemon entry point (runs inside the spawned process)
# ---------------------------------------------------------------------------

def _daemon_main(startup_state_path: Optional[Path] = None) -> None:
    """Main loop executed inside the daemon process."""
    try:
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
        run_watcher(
            watched_dirs,
            handler,
            on_started=lambda: _write_startup_state(startup_state_path, "ready"),
        )
        logger.info("EnvGuard daemon stopped")
    except Exception as exc:  # noqa: BLE001
        _write_startup_state(startup_state_path, "error", str(exc))
        _write_startup_crash(exc)
        raise
    finally:
        _remove_pid()
        _clear_startup_state(startup_state_path) if startup_state_path else None


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
        # Parent: write PID and wait for startup handshake.
        _write_pid(pid)
        ok, msg = _wait_for_startup(pid)
        if not ok:
            _remove_pid()
            return False, msg
        return True, msg

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
        _daemon_main(startup_state_path=_startup_state_path(os.getpid()))
    except Exception as exc:  # noqa: BLE001
        _write_startup_crash(exc)
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
    ok, msg = _wait_for_startup(proc.pid)
    if not ok or proc.poll() is not None or not _process_is_running(proc.pid):
        _remove_pid()
        return False, msg
    return True, msg


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
    ok, msg = _wait_for_startup(proc.pid)
    if not ok or proc.poll() is not None or not _process_is_running(proc.pid):
        _remove_pid()
        return False, msg
    return True, msg


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
    if pid is not None and not running:
        _remove_pid()
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
