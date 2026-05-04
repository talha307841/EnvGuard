"""
File system event handler for EnvGuard.

Uses the watchdog library to monitor directories for .env file access events.
When a .env file is opened/read, logs the access and creates a masked temp copy.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileOpenedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from envguard.config import get_log_path, load_config
from envguard.masker import mask_env_content

logger = logging.getLogger(__name__)


def _is_env_file(path: str) -> bool:
    """Return True if the path looks like a .env file."""
    name = os.path.basename(path)
    # Match .env, .env.local, .env.production, etc.
    return name == ".env" or name.startswith(".env.")


def _get_accessing_process() -> str:
    """Best-effort attempt to identify the process that triggered the event."""
    # watchdog does not expose the reading process directly.
    # We record our own PID as the watcher; for real interception a kernel-level
    # tool (inotify + /proc) would be needed. We log what we can.
    import psutil  # type: ignore
    try:
        proc = psutil.Process(os.getpid())
        # Walk up parent chain looking for a known coding agent
        chain = []
        p: Optional[psutil.Process] = proc
        while p is not None:
            try:
                name = p.name()
                chain.append(f"{name}(pid={p.pid})")
                p = p.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        return " -> ".join(reversed(chain))
    except Exception:
        return f"pid={os.getpid()}"


def _detect_coding_agent(file_path: str) -> str:
    """Best-effort detection of known coding agents touching a target file."""
    try:
        import psutil  # type: ignore

        agent_keywords = {
            "copilot": ["copilot", "github-copilot"],
            "cursor": ["cursor"],
            "claude": ["claude"],
            "code": ["code", "code-insiders", "vscode"],
            "aider": ["aider"],
        }

        path_norm = os.path.realpath(file_path)
        fallback_hits: list[str] = []

        for proc in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdline_list = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdline_list).lower()
                identity = f"{name} {cmdline}"

                matched_label = None
                for label, words in agent_keywords.items():
                    if any(word in identity for word in words):
                        matched_label = label
                        break

                if not matched_label:
                    continue

                fallback_hits.append(matched_label)

                # Strong match: process has this file open right now.
                try:
                    for opened in proc.open_files():
                        if os.path.realpath(opened.path) == path_norm:
                            return matched_label
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                    pass
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue

        return fallback_hits[0] if fallback_hits else "unknown"
    except Exception:
        return "unknown"


# Debounce window: suppress duplicate events for the same file within this many seconds.
_DEBOUNCE_SECONDS = 1.0


class EnvFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that intercepts .env file access events."""

    def __init__(
        self,
        log_path: Path,
        events_path: Path,
        safe_keys: set[str],
        mask_char: str,
        keep_prefix_chars: int,
    ):
        super().__init__()
        self.log_path = log_path
        self.events_path = events_path
        self.safe_keys = safe_keys
        self.mask_char = mask_char
        self.keep_prefix_chars = keep_prefix_chars
        # Ensure log dir exists
        log_path.parent.mkdir(parents=True, exist_ok=True)
        events_path.parent.mkdir(parents=True, exist_ok=True)
        # Re-entrance guard: paths currently being masked by us (to avoid self-triggering).
        self._masking: set[str] = set()
        self._masking_lock = threading.Lock()
        # Debounce: last time we logged each path.
        self._last_seen: dict[str, float] = {}
        self._debounce_lock = threading.Lock()

    def _log_access(self, event_type: str, file_path: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        process_info = _get_accessing_process()
        entry = f"{ts} | {event_type:10} | {process_info} | {file_path}\n"
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(entry)
        except OSError as exc:
            logger.warning("Failed to write access log: %s", exc)
        logger.info("ACCESS %s %s [%s]", event_type, file_path, process_info)

    def _write_event_record(
        self,
        event_type: str,
        file_path: str,
        masked_file_path: Optional[str],
        results,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        process_info = _get_accessing_process()
        agent = _detect_coding_agent(file_path)
        masked_items = [
            {
                "key": r.key,
                "masked_value": r.masked_value,
                "was_masked": bool(r.was_masked),
            }
            for r in results
        ]
        masked_count = sum(1 for r in results if r.was_masked)
        llm_view = [f"{r.key}={r.masked_value}" for r in results]
        record = {
            "timestamp": ts,
            "event_type": event_type,
            "file_path": file_path,
            "process_info": process_info,
            "agent": agent,
            "masked_file_path": masked_file_path,
            "masked_count": masked_count,
            "total_keys": len(results),
            "saved_you": masked_count > 0,
            "masked_items": masked_items,
            "llm_view": llm_view,
        }
        try:
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True) + "\n")
        except OSError as exc:
            logger.warning("Failed to write dashboard event log: %s", exc)

    def _is_debounced(self, src_path: str) -> bool:
        """Return True if this path was already handled within the debounce window."""
        now = time.monotonic()
        with self._debounce_lock:
            last = self._last_seen.get(src_path, 0.0)
            if now - last < _DEBOUNCE_SECONDS:
                return True
            self._last_seen[src_path] = now
        return False

    def _handle_env_access(self, event_type: str, src_path: str) -> None:
        if not _is_env_file(src_path):
            return
        # Skip if EnvGuard itself is currently reading this file for masking.
        with self._masking_lock:
            if src_path in self._masking:
                return
        # Suppress rapid duplicate events for the same file.
        if self._is_debounced(src_path):
            return
        self._log_access(event_type, src_path)
        with self._masking_lock:
            self._masking.add(src_path)
        try:
            content = Path(src_path).read_text(encoding="utf-8")
            _, results = mask_env_content(
                content,
                safe_keys=self.safe_keys,
                mask_char=self.mask_char,
                keep_prefix_chars=self.keep_prefix_chars,
            )
            masked_count = sum(1 for r in results if r.was_masked)
            logger.info(
                "Masked %d/%d values in %s (in-memory preview)",
                masked_count,
                len(results),
                src_path,
            )
            self._write_event_record(
                event_type=event_type,
                file_path=src_path,
                masked_file_path=None,
                results=results,
            )
        except Exception as exc:
            logger.error("Failed to mask %s: %s", src_path, exc)
        finally:
            with self._masking_lock:
                self._masking.discard(src_path)

    # watchdog fires on_modified for writes; on_created for new files.
    # True "read" interception requires OS-level hooks (inotify IN_ACCESS etc.)
    # which are outside watchdog's scope. We log and mask on modification/creation
    # events so agents that write-then-read (e.g. file caching) are covered.

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        if not event.is_directory:
            self._handle_env_access("CREATED", str(event.src_path))

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if not event.is_directory:
            self._handle_env_access("MODIFIED", str(event.src_path))

    def on_opened(self, event: FileOpenedEvent) -> None:  # type: ignore[override]
        # FileOpenedEvent is available in watchdog 4.x and is the closest cross-platform
        # signal for read/open attempts on .env files.
        if not event.is_directory:
            self._handle_env_access("OPENED", str(event.src_path))


def _make_observer() -> Observer:
    """Return an Observer with IN_OPEN added to the inotify event mask on Linux.

    watchdog's default inotify mask omits IN_OPEN, so pure reads (e.g. an IDE
    or coding agent opening a .env file) never fire FileOpenedEvent.  We patch
    the emitter class to include IN_OPEN before any watch is scheduled.
    Falls back to the stock Observer on all other platforms.
    """
    if sys.platform != "linux":
        return Observer()
    try:
        from watchdog.observers.inotify import InotifyEmitter  # type: ignore[attr-defined]
        from watchdog.observers.inotify_c import InotifyFlags  # type: ignore[attr-defined]

        class _OpenAwareEmitter(InotifyEmitter):  # type: ignore[misc]
            EVENT_MASK = InotifyEmitter.EVENT_MASK | InotifyFlags.IN_OPEN

        obs = Observer()
        obs._emitter_class = _OpenAwareEmitter  # type: ignore[attr-defined]
        return obs
    except Exception:
        logger.warning(
            "Could not enable IN_OPEN inotify events; "
            "file-read events may not be detected. Falling back to default observer."
        )
        return Observer()


def build_observer(watched_dirs: list[Path], handler: EnvFileEventHandler) -> Observer:
    """Create and configure a watchdog Observer for the given directories."""
    observer = _make_observer()
    for directory in watched_dirs:
        if directory.is_dir():
            observer.schedule(handler, str(directory), recursive=True)
            logger.info("Watching directory: %s", directory)
        else:
            logger.warning("Skipping non-existent directory: %s", directory)
    return observer


def run_watcher(
    watched_dirs: list[Path],
    handler: EnvFileEventHandler,
    on_started: Optional[Callable[[], None]] = None,
) -> None:
    """Start the observer and block until interrupted."""
    observer = build_observer(watched_dirs, handler)
    try:
        observer.start()
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise RuntimeError(
                "inotify watch limit reached. "
                "Too many subdirectories are being watched. "
                "Fix by running:\n"
                "  echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf\n"
                "  sudo sysctl -p\n"
                "Or watch a more specific subdirectory instead of a large tree."
            ) from exc
        raise
    if on_started is not None:
        on_started()
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        observer.stop()
    observer.join()
