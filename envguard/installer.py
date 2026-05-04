"""
Platform-specific startup registration for EnvGuard.

- macOS  : launchd plist in ~/Library/LaunchAgents/
- Linux  : systemd user service in ~/.config/systemd/user/
- Windows: Task Scheduler entry at login
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_LABEL = "com.envguard.daemon"
_SERVICE_NAME = "envguard"


def _python_executable() -> str:
    return sys.executable


def _envguard_cmd() -> str:
    """Return the path to the envguard CLI script."""
    # When installed via pip, 'envguard' will be on PATH beside the python bin.
    scripts_dir = Path(_python_executable()).parent
    for candidate in ("envguard", "envguard.exe"):
        p = scripts_dir / candidate
        if p.exists():
            return str(p)
    # Fallback: run as module
    return f"{_python_executable()} -m envguard.cli"


# ---------------------------------------------------------------------------
# macOS — launchd
# ---------------------------------------------------------------------------

_LAUNCHD_PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{_LABEL}.plist"

_LAUNCHD_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>envguard.cli</string>
        <string>_run_daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>{home}/.envguard/launchd_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{home}/.envguard/launchd_stderr.log</string>
</dict>
</plist>
"""


def install_macos() -> tuple[bool, str]:
    plist_path = _LAUNCHD_PLIST_PATH
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    content = _LAUNCHD_PLIST_TEMPLATE.format(
        label=_LABEL,
        python=_python_executable(),
        home=str(Path.home()),
    )
    plist_path.write_text(content, encoding="utf-8")
    try:
        subprocess.run(
            ["launchctl", "load", str(plist_path)],
            check=True,
            capture_output=True,
        )
        return True, f"Registered with launchd: {plist_path}"
    except subprocess.CalledProcessError as exc:
        return False, f"launchctl load failed: {exc.stderr.decode().strip()}"


def uninstall_macos() -> tuple[bool, str]:
    if _LAUNCHD_PLIST_PATH.exists():
        try:
            subprocess.run(
                ["launchctl", "unload", str(_LAUNCHD_PLIST_PATH)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError:
            pass  # Already unloaded
        _LAUNCHD_PLIST_PATH.unlink(missing_ok=True)
        return True, "Removed launchd plist"
    return False, "No launchd plist found"


# ---------------------------------------------------------------------------
# Linux — systemd user service
# ---------------------------------------------------------------------------

_SYSTEMD_DIR = Path.home() / ".config" / "systemd" / "user"
_SYSTEMD_SERVICE_PATH = _SYSTEMD_DIR / f"{_SERVICE_NAME}.service"

_SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=EnvGuard — .env file protection daemon
After=default.target

[Service]
Type=simple
ExecStart={python} -m envguard.cli _run_daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


def install_linux() -> tuple[bool, str]:
    _SYSTEMD_DIR.mkdir(parents=True, exist_ok=True)
    content = _SYSTEMD_UNIT_TEMPLATE.format(python=_python_executable())
    _SYSTEMD_SERVICE_PATH.write_text(content, encoding="utf-8")

    msgs: list[str] = [f"Wrote unit file: {_SYSTEMD_SERVICE_PATH}"]
    for cmd in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", _SERVICE_NAME],
        ["systemctl", "--user", "start", _SERVICE_NAME],
    ):
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            msgs.append(f"OK: {' '.join(cmd)}")
        except subprocess.CalledProcessError as exc:
            msgs.append(f"WARN: {' '.join(cmd)} → {exc.stderr.decode().strip()}")

    return True, "\n".join(msgs)


def uninstall_linux() -> tuple[bool, str]:
    msgs: list[str] = []
    for cmd in (
        ["systemctl", "--user", "stop", _SERVICE_NAME],
        ["systemctl", "--user", "disable", _SERVICE_NAME],
    ):
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            pass

    if _SYSTEMD_SERVICE_PATH.exists():
        _SYSTEMD_SERVICE_PATH.unlink()
        msgs.append(f"Removed: {_SYSTEMD_SERVICE_PATH}")

    try:
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass

    return True, "\n".join(msgs) if msgs else "Nothing to remove"


# ---------------------------------------------------------------------------
# Windows — Task Scheduler
# ---------------------------------------------------------------------------

_TASK_NAME = "EnvGuard"

_SCHTASKS_XML_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{python}</Command>
      <Arguments>-m envguard.cli _run_daemon</Arguments>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
  </Settings>
</Task>
"""


def install_windows() -> tuple[bool, str]:
    import tempfile

    xml_content = _SCHTASKS_XML_TEMPLATE.format(python=_python_executable())
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-16"
    ) as tmp:
        tmp.write(xml_content)
        xml_path = tmp.name

    try:
        subprocess.run(
            [
                "schtasks",
                "/Create",
                "/F",
                "/TN", _TASK_NAME,
                "/XML", xml_path,
            ],
            check=True,
            capture_output=True,
        )
        return True, f"Task '{_TASK_NAME}' registered in Task Scheduler"
    except subprocess.CalledProcessError as exc:
        return False, f"schtasks failed: {exc.stderr.decode().strip()}"
    except FileNotFoundError:
        return False, "schtasks.exe not found — are you on Windows?"
    finally:
        Path(xml_path).unlink(missing_ok=True)


def uninstall_windows() -> tuple[bool, str]:
    try:
        subprocess.run(
            ["schtasks", "/Delete", "/F", "/TN", _TASK_NAME],
            check=True,
            capture_output=True,
        )
        return True, f"Task '{_TASK_NAME}' removed from Task Scheduler"
    except subprocess.CalledProcessError as exc:
        return False, f"schtasks failed: {exc.stderr.decode().strip()}"
    except FileNotFoundError:
        return False, "schtasks.exe not found"


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def install_startup() -> tuple[bool, str]:
    """Register EnvGuard to start on login for the current platform."""
    if sys.platform == "darwin":
        return install_macos()
    elif sys.platform.startswith("linux"):
        return install_linux()
    elif sys.platform == "win32":
        return install_windows()
    else:
        return False, f"Unsupported platform: {sys.platform}"


def uninstall_startup() -> tuple[bool, str]:
    """Remove EnvGuard from startup for the current platform."""
    if sys.platform == "darwin":
        return uninstall_macos()
    elif sys.platform.startswith("linux"):
        return uninstall_linux()
    elif sys.platform == "win32":
        return uninstall_windows()
    else:
        return False, f"Unsupported platform: {sys.platform}"
