"""Malicious pattern detector for scankii.

Scans raw file contents (not AST) for malicious patterns like reverse shells,
remote fetch-execute, base64 obfuscation, credential theft, and more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RULES_PATH = Path(__file__).resolve().parent.parent.parent / "rules" / "malicious.yaml"


@dataclass(frozen=True)
class MaliciousFinding:
    """A finding from malicious pattern scanning."""

    file_path: str
    line_number: int
    pattern_id: str
    pattern_name: str
    matched_text: str
    severity: Severity
    attack_category: str


def scan_file(
    file_path: str | Path,
    rules_path: Path | None = None,
) -> list[MaliciousFinding]:
    """Scan a file for malicious patterns.

    Reads the file as raw text and matches against patterns from malicious.yaml.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        return []

    content = file_path.read_text(encoding="utf-8", errors="replace")
    return scan_content(content, str(file_path), rules_path)


def scan_content(
    content: str,
    file_path: str = "<string>",
    rules_path: Path | None = None,
) -> list[MaliciousFinding]:
    """Scan raw text content for malicious patterns."""
    patterns = _load_patterns(rules_path or RULES_PATH)
    findings: list[MaliciousFinding] = []

    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        for pattern_info in patterns:
            regex = pattern_info["compiled"]
            match = regex.search(line)
            if match:
                findings.append(
                    MaliciousFinding(
                        file_path=file_path,
                        line_number=line_num,
                        pattern_id=pattern_info["id"],
                        pattern_name=pattern_info["name"],
                        matched_text=match.group(0),
                        severity=pattern_info["severity"],
                        attack_category=pattern_info["attack_category"],
                    )
                )

    return findings


def _load_patterns(path: Path) -> list[dict[str, Any]]:
    """Load and compile malicious patterns from YAML."""
    with path.open(encoding="utf-8") as fh:
        entries = yaml.safe_load(fh)

    patterns: list[dict[str, Any]] = []
    for entry in entries:
        try:
            compiled = re.compile(entry["pattern"])
        except re.error:
            continue

        patterns.append({
            "id": entry["id"],
            "name": entry["name"],
            "compiled": compiled,
            "severity": entry["severity"],
            "attack_category": entry["attack_category"],
        })

    return patterns
