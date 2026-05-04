"""
Click-based CLI entry point for EnvGuard.

Commands:
  envguard start          — start the daemon
  envguard stop           — stop the daemon
  envguard status         — show running status + last 10 log lines
  envguard add <path>     — add a directory to watch
  envguard log            — show full access log
  envguard install        — register EnvGuard for system startup
  envguard uninstall      — remove EnvGuard from system startup
  envguard mask <file>    — mask a .env file (prints result or writes temp file)
  envguard _run_daemon    — internal: run daemon in foreground (used by OS launchers)
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from envguard import __version__
from envguard.config import add_watched_dir, load_config, resolve_watched_dirs
from envguard.daemon import get_log_lines, get_status, start_daemon, stop_daemon
from envguard.installer import install_startup, uninstall_startup


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _ok(msg: str) -> None:
    click.secho(f"  ✓  {msg}", fg="green")


def _warn(msg: str) -> None:
    click.secho(f"  !  {msg}", fg="yellow")


def _err(msg: str) -> None:
    click.secho(f"  ✗  {msg}", fg="red", err=True)


def _info(msg: str) -> None:
    click.echo(f"     {msg}")


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(__version__, prog_name="envguard")
def cli() -> None:
    """EnvGuard — protect .env files from being read by coding agents."""


# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------

@cli.command()
def start() -> None:
    """Start the EnvGuard daemon."""
    success, msg = start_daemon()
    if success:
        _ok(msg)
    else:
        _warn(msg)
        sys.exit(1)


# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------

@cli.command()
def stop() -> None:
    """Stop the EnvGuard daemon."""
    success, msg = stop_daemon()
    if success:
        _ok(msg)
    else:
        _warn(msg)
        sys.exit(1)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
def status() -> None:
    """Show daemon status, watched directories, and last 10 log entries."""
    s = get_status()

    if s["running"]:
        click.secho(f"  EnvGuard is RUNNING  (pid={s['pid']})", fg="green", bold=True)
    else:
        click.secho("  EnvGuard is STOPPED", fg="red", bold=True)

    click.echo()
    click.secho("  Watched directories:", bold=True)
    if s["watched_dirs"]:
        for d in s["watched_dirs"]:
            _info(d)
    else:
        _warn("No directories configured. Use: envguard add <path>")

    click.echo()
    click.secho("  Last 10 access log entries:", bold=True)
    lines = get_log_lines(10)
    if lines:
        for line in lines:
            _log_line_colored(line)
    else:
        _info("(no entries yet)")


def _log_line_colored(line: str) -> None:
    lower = line.lower()
    if "accessed" in lower:
        click.secho(f"  {line}", fg="yellow")
    elif "error" in lower or "blocked" in lower:
        click.secho(f"  {line}", fg="red")
    else:
        click.secho(f"  {line}", fg="white")


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------

@cli.command("add")
@click.argument("path")
def add_dir(path: str) -> None:
    """Add a directory PATH to the watch list."""
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        _warn(f"Directory does not exist: {resolved}")
        _warn("Adding anyway — it will be skipped until it exists.")
    add_watched_dir(str(resolved))
    _ok(f"Added to watch list: {resolved}")
    _info("Restart EnvGuard for the change to take effect: envguard stop && envguard start")


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------

@cli.command("log")
@click.option("--tail", "-n", default=0, type=int, help="Show only the last N lines (0 = all).")
def show_log(tail: int) -> None:
    """Show the full access log."""
    lines = get_log_lines(tail if tail > 0 else None)
    if not lines:
        _info("Access log is empty.")
        return
    for line in lines:
        _log_line_colored(line)


# ---------------------------------------------------------------------------
# install / uninstall (startup)
# ---------------------------------------------------------------------------

@cli.command("install")
def install_cmd() -> None:
    """Register EnvGuard to start automatically at login."""
    success, msg = install_startup()
    if success:
        _ok(msg)
    else:
        _err(msg)
        sys.exit(1)


@cli.command("uninstall")
def uninstall_cmd() -> None:
    """Remove EnvGuard from automatic startup."""
    success, msg = uninstall_startup()
    if success:
        _ok(msg)
    else:
        _err(msg)
        sys.exit(1)


# ---------------------------------------------------------------------------
# mask  (manual masking with --dry-run support)
# ---------------------------------------------------------------------------

@cli.command("mask")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--dry-run", is_flag=True, default=False, help="Print masking results without writing a file.")
def mask_cmd(file: Path, dry_run: bool) -> None:
    """Mask secret values in a .env FILE.

    \b
    Without --dry-run: writes a masked copy to a temp file and prints the path.
    With    --dry-run: prints which keys would be masked (no files written).
    """
    from envguard.masker import mask_env_file

    config = load_config()
    safe_keys = set(config.get("safe_keys", []))
    mask_char = config.get("mask_char", "*")
    keep_prefix_chars = int(config.get("keep_prefix_chars", 3))

    tmp_path, results = mask_env_file(
        file,
        safe_keys=safe_keys,
        mask_char=mask_char,
        keep_prefix_chars=keep_prefix_chars,
        dry_run=dry_run,
    )

    if dry_run:
        click.echo()
        click.secho("  Dry-run complete. No files written.", fg="cyan")
        return

    masked_count = sum(1 for r in results if r.was_masked)
    click.secho(
        f"  Masked {masked_count}/{len(results)} values → ",
        fg="yellow",
        nl=False,
    )
    click.secho(str(tmp_path), fg="cyan")


# ---------------------------------------------------------------------------
# _run_daemon  (internal — called by OS launchers)
# ---------------------------------------------------------------------------

@cli.command("_run_daemon", hidden=True)
def run_daemon_fg() -> None:
    """Run the daemon in the foreground (used by OS startup entries)."""
    from envguard.daemon import _daemon_main

    _daemon_main()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli()


if __name__ == "__main__":
    main()
