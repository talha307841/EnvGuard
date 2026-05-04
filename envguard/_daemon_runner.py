"""
Daemon runner module — used as the subprocess entry point on platforms
where os.fork() is unavailable (Windows, or fallback).

Run with: python -m envguard._daemon_runner
"""

import os
import sys

# Ensure the package root is importable if run directly
_pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from envguard.daemon import _daemon_main  # noqa: E402

if __name__ == "__main__":
    _daemon_main()
