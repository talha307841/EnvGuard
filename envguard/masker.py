"""
.env parsing and value masking logic for EnvGuard.

Masking rules:
- KEY=value → KEY=val*** (keep first keep_prefix_chars chars, mask the rest)
- If value length < 6  → KEY=***
- Never mask keys in safe_keys list
- Preserve comments (lines starting with #) and blank lines as-is
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Optional

# Default safe keys that should never be masked
DEFAULT_SAFE_KEYS = {"NODE_ENV", "PORT", "HOST", "APP_ENV", "DEBUG", "LOG_LEVEL"}

# Pattern for a valid .env assignment line: KEY=value or KEY="value" or KEY='value'
_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)")


class MaskResult:
    """Result of masking a single line."""

    def __init__(self, key: str, original_value: str, masked_value: str, was_masked: bool):
        self.key = key
        self.original_value = original_value
        self.masked_value = masked_value
        self.was_masked = was_masked

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"MaskResult(key={self.key!r}, original={self.original_value!r}, "
            f"masked={self.masked_value!r}, was_masked={self.was_masked})"
        )


def _strip_quotes(value: str) -> tuple[str, str, str]:
    """Return (prefix_quote, inner_value, suffix_quote) from a possibly-quoted value."""
    if len(value) >= 2 and value[0] in ('"', "'") and value[-1] == value[0]:
        return value[0], value[1:-1], value[-1]
    return "", value, ""


def mask_value(
    value: str,
    mask_char: str = "*",
    keep_prefix_chars: int = 3,
) -> tuple[str, bool]:
    """
    Mask a single value string.

    Returns (masked_value, was_masked).
    """
    quote_open, inner, quote_close = _strip_quotes(value)
    if len(inner) < 6:
        return f"{quote_open}{mask_char * 3}{quote_close}", True
    prefix = inner[:keep_prefix_chars]
    masked = f"{quote_open}{prefix}{mask_char * 3}{quote_close}"
    return masked, True


def mask_line(
    line: str,
    safe_keys: Optional[set[str]] = None,
    mask_char: str = "*",
    keep_prefix_chars: int = 3,
) -> tuple[str, Optional[MaskResult]]:
    """
    Process a single line from a .env file.

    Returns (output_line, MaskResult | None).
    MaskResult is None for non-assignment lines (comments, blanks, unrecognised).
    """
    if safe_keys is None:
        safe_keys = DEFAULT_SAFE_KEYS

    stripped = line.rstrip("\n")

    # Blank line or comment — pass through unchanged
    if not stripped or stripped.lstrip().startswith("#"):
        return line, None

    m = _LINE_RE.match(stripped)
    if not m:
        # Not a key=value line — pass through
        return line, None

    key = m.group(1)
    value = m.group(2)

    if key in safe_keys:
        return line, MaskResult(key, value, value, was_masked=False)

    masked, was_masked = mask_value(value, mask_char=mask_char, keep_prefix_chars=keep_prefix_chars)

    # Preserve trailing newline
    nl = "\n" if line.endswith("\n") else ""
    output = f"{key}={masked}{nl}"
    return output, MaskResult(key, value, masked, was_masked=was_masked)


def mask_env_content(
    content: str,
    safe_keys: Optional[set[str]] = None,
    mask_char: str = "*",
    keep_prefix_chars: int = 3,
) -> tuple[str, list[MaskResult]]:
    """
    Mask all secret values in a .env file content string.

    Returns (masked_content, list_of_MaskResults).
    """
    if safe_keys is None:
        safe_keys = DEFAULT_SAFE_KEYS

    lines = content.splitlines(keepends=True)
    output_lines: list[str] = []
    results: list[MaskResult] = []

    for line in lines:
        out_line, result = mask_line(
            line, safe_keys=safe_keys, mask_char=mask_char, keep_prefix_chars=keep_prefix_chars
        )
        output_lines.append(out_line)
        if result is not None:
            results.append(result)

    return "".join(output_lines), results


def mask_env_file(
    source_path: Path,
    safe_keys: Optional[set[str]] = None,
    mask_char: str = "*",
    keep_prefix_chars: int = 3,
    dry_run: bool = False,
) -> tuple[Optional[Path], list[MaskResult]]:
    """
    Read a .env file, mask secret values, write masked content to a temp file.

    Returns (temp_file_path, list_of_MaskResults).
    If dry_run=True, prints what would be masked and returns (None, results).
    Original file is NEVER modified.
    """
    content = source_path.read_text(encoding="utf-8")
    masked_content, results = mask_env_content(
        content,
        safe_keys=safe_keys,
        mask_char=mask_char,
        keep_prefix_chars=keep_prefix_chars,
    )

    if dry_run:
        _print_dry_run(results)
        return None, results

    # Write to a temp file next to the original (same directory for locality)
    fd, tmp_path = tempfile.mkstemp(
        prefix=".envguard_masked_", suffix=".env", dir=source_path.parent
    )
    try:
        with open(fd, "w", encoding="utf-8") as f:
            f.write(masked_content)
    except Exception:
        import os
        os.close(fd)
        raise

    return Path(tmp_path), results


def _print_dry_run(results: list[MaskResult]) -> None:  # pragma: no cover
    """Print dry-run masking summary with color coding."""
    try:
        import click

        for r in results:
            if not r.was_masked:
                click.secho(f"  SAFE    {r.key}={r.original_value}", fg="green")
            else:
                click.secho(f"  MASKED  {r.key}={r.masked_value}  (was: {r.original_value})", fg="yellow")
    except ImportError:
        for r in results:
            status = "SAFE" if not r.was_masked else "MASKED"
            print(f"  {status:7} {r.key}={r.masked_value}")
