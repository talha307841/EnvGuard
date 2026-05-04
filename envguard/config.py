"""Config read/write helpers for EnvGuard."""

import json
import os
from pathlib import Path
from typing import Any

ENVGUARD_DIR = Path.home() / ".envguard"
CONFIG_PATH = ENVGUARD_DIR / "config.json"
PID_PATH = ENVGUARD_DIR / "envguard.pid"

DEFAULT_CONFIG: dict[str, Any] = {
    "watched_dirs": [],
    "safe_keys": ["NODE_ENV", "PORT", "HOST", "APP_ENV", "DEBUG", "LOG_LEVEL"],
    "log_file": str(ENVGUARD_DIR / "access.log"),
    "events_file": str(ENVGUARD_DIR / "events.jsonl"),
    "mask_char": "*",
    "keep_prefix_chars": 3,
    "dashboard_port": 8787,
}


def ensure_envguard_dir() -> None:
    ENVGUARD_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict[str, Any]:
    ensure_envguard_dir()
    if not CONFIG_PATH.exists():
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Merge with defaults for any missing keys
    merged = dict(DEFAULT_CONFIG)
    merged.update(data)
    return merged


def save_config(config: dict[str, Any]) -> None:
    ensure_envguard_dir()
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def resolve_watched_dirs(config: dict[str, Any]) -> list[Path]:
    return [Path(os.path.expanduser(d)) for d in config.get("watched_dirs", [])]


def add_watched_dir(path: str) -> None:
    config = load_config()
    expanded = str(Path(os.path.expanduser(path)))
    dirs = config.get("watched_dirs", [])
    if expanded not in dirs:
        dirs.append(expanded)
        config["watched_dirs"] = dirs
        save_config(config)


def get_log_path(config: dict[str, Any]) -> Path:
    return Path(os.path.expanduser(config.get("log_file", str(ENVGUARD_DIR / "access.log"))))


def get_events_path(config: dict[str, Any]) -> Path:
    return Path(os.path.expanduser(config.get("events_file", str(ENVGUARD_DIR / "events.jsonl"))))
