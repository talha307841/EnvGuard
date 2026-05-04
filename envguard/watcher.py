"""
File system event handler for EnvGuard.

Uses the watchdog library to monitor directories for .env file access events.
When a .env file is opened/read, logs the access and creates a masked temp copy.
"""

from __future__ import annotations

import logging
import os
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
from envguard.masker import mask_env_file

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


class EnvFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that intercepts .env file access events."""

    def __init__(self, log_path: Path, safe_keys: set[str], mask_char: str, keep_prefix_chars: int):
        super().__init__()
        self.log_path = log_path
        self.safe_keys = safe_keys
        self.mask_char = mask_char
        self.keep_prefix_chars = keep_prefix_chars
        # Ensure log dir exists
        log_path.parent.mkdir(parents=True, exist_ok=True)

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

    def _handle_env_access(self, event_type: str, src_path: str) -> None:
        if not _is_env_file(src_path):
            return
        self._log_access(event_type, src_path)
        try:
            tmp_path, results = mask_env_file(
                Path(src_path),
                safe_keys=self.safe_keys,
                mask_char=self.mask_char,
                keep_prefix_chars=self.keep_prefix_chars,
            )
            masked_count = sum(1 for r in results if r.was_masked)
            logger.info(
                "Masked %d/%d values in %s → %s",
                masked_count,
                len(results),
                src_path,
                tmp_path,
            )
        except Exception as exc:
            logger.error("Failed to mask %s: %s", src_path, exc)

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


def build_observer(watched_dirs: list[Path], handler: EnvFileEventHandler) -> Observer:
    """Create and configure a watchdog Observer for the given directories."""
    observer = Observer()
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
    observer.start()
    if on_started is not None:
        on_started()
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        observer.stop()
    observer.join()
