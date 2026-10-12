"""Minimal ANSI color helpers with automatic terminal detection.

No third-party dependency: the modem tool stays stdlib-only. Color is emitted
only when the caller opts in via :class:`Palette`, which the CLI enables only
for an interactive TTY and disables for pipes, ``--json``, ``--no-color``, or
the ``NO_COLOR`` convention (https://no-color.org).
"""

from __future__ import annotations

import os
import sys
from typing import IO

_RESET = "\033[0m"
_CODES = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


class Palette:
    """Wraps text in ANSI codes, or returns it unchanged when disabled."""

    def __init__(self, *, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *styles: str) -> str:
        """Return ``text`` wrapped in the named ANSI styles when enabled."""
        if not self.enabled or not styles:
            return text
        prefix = "".join(_CODES[style] for style in styles if style in _CODES)
        if not prefix:
            return text
        return f"{prefix}{text}{_RESET}"


def should_colorize(stream: IO[str], *, force_off: bool) -> bool:
    """Decide whether to emit color for ``stream``.

    Color is suppressed when explicitly turned off, when ``NO_COLOR`` is set,
    or when the stream is not an interactive terminal (e.g. a pipe or file).
    """
    if force_off:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def palette_for(stream: IO[str] = sys.stdout, *, force_off: bool = False) -> Palette:
    """Return a :class:`Palette` configured for ``stream``."""
    return Palette(enabled=should_colorize(stream, force_off=force_off))
