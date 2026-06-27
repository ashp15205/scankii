"""SafeLogger: drop-in replacement for print/logging that redacts credentials.

This module scans output strings for credential patterns and replaces matched
values with PROVIDER-[REDACTED] before writing to the output stream.
"""

from __future__ import annotations

import builtins
import logging
import re
import sys
from pathlib import Path
from typing import Any, TextIO

import yaml

_RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "credentials.yaml"

# Cache compiled patterns
_PATTERNS: list[tuple[re.Pattern, str]] | None = None


def _load_patterns(rules_path: Path | None = None) -> list[tuple[re.Pattern, str]]:
    """Load and compile credential patterns from YAML.

    Returns a list of (compiled_regex, redaction_prefix) tuples.
    """
    global _PATTERNS
    if _PATTERNS is not None and rules_path is None:
        return _PATTERNS

    path = rules_path or _RULES_PATH
    with path.open(encoding="utf-8") as fh:
        entries = yaml.safe_load(fh)

    patterns: list[tuple[re.Pattern, str]] = []
    for entry in entries:
        pattern_str = entry["pattern"]
        entry_id = entry.get("id", "")

        # Determine a redaction prefix from the pattern
        prefix = _extract_prefix(pattern_str, entry_id)

        try:
            compiled = re.compile(pattern_str)
            patterns.append((compiled, prefix))
        except re.error:
            continue

    # Always update the cache
    _PATTERNS = patterns
    return patterns


def _extract_prefix(pattern_str: str, entry_id: str) -> str:
    """Extract a short prefix for redaction labels from the pattern."""
    # Try to find a literal prefix in the pattern
    # Common prefixes: sk-, gsk_, AKIA, ghp_, AIza, xoxb-, mongodb, postgres, mysql
    for literal in ("sk-", "gsk_", "AKIA", "ghp_", "AIza", "xoxb-",
                     "mongodb", "postgres", "mysql"):
        if literal in pattern_str:
            return literal.rstrip("-_")

    if "PRIVATE KEY" in pattern_str:
        return "KEY"

    if "os.environ" in pattern_str or "process.env" in pattern_str:
        return "ENV"

    # Fallback to entry ID
    return entry_id.upper().replace("-", "_")


def redact(text: str, rules_path: Path | None = None) -> str:
    """Scan text for credential patterns and redact matched values.

    Matched values are replaced with PREFIX-[REDACTED].
    """
    patterns = _load_patterns(rules_path)
    result = text
    for regex, prefix in patterns:
        result = regex.sub(f"{prefix}-[REDACTED]", result)
    return result


class SafeLogger:
    """A credential-redacting logger.

    Drop-in replacement for basic logging with automatic credential redaction.
    """

    def __init__(
        self,
        name: str = "scankii",
        stream: TextIO | None = None,
        rules_path: Path | None = None,
    ) -> None:
        self._logger = logging.getLogger(name)
        if not self._logger.handlers:
            handler = logging.StreamHandler(stream or sys.stderr)
            handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
            self._logger.addHandler(handler)
            self._logger.setLevel(logging.DEBUG)
        self._rules_path = rules_path

    def _redact(self, msg: str) -> str:
        return redact(msg, self._rules_path)

    def _format_args(self, *args: Any, **kwargs: Any) -> str:
        parts = [str(a) for a in args]
        return " ".join(parts)

    def info(self, *args: Any, **kwargs: Any) -> None:
        """Log at INFO level with credential redaction."""
        self._logger.info(self._redact(self._format_args(*args)))

    def debug(self, *args: Any, **kwargs: Any) -> None:
        """Log at DEBUG level with credential redaction."""
        self._logger.debug(self._redact(self._format_args(*args)))

    def warning(self, *args: Any, **kwargs: Any) -> None:
        """Log at WARNING level with credential redaction."""
        self._logger.warning(self._redact(self._format_args(*args)))

    def error(self, *args: Any, **kwargs: Any) -> None:
        """Log at ERROR level with credential redaction."""
        self._logger.error(self._redact(self._format_args(*args)))


def safe_print(*args: Any, sep: str = " ", end: str = "\n",
               file: TextIO | None = None, flush: bool = False,
               rules_path: Path | None = None) -> None:
    """Drop-in replacement for print() that redacts credentials.

    Usage:
        from scankii.runtime.safe_logger import safe_print
        safe_print(f"Key is {api_key}")  # Key is sk-[REDACTED]
    """
    output = sep.join(str(a) for a in args)
    output = redact(output, rules_path)
    builtins.print(output, end=end, file=file, flush=flush)
