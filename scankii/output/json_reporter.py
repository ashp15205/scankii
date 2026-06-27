"""JSON reporter for scankii scan results."""

from __future__ import annotations

from pathlib import Path

from scankii.scanner import ScanResult


def save_json_report(result: ScanResult, output_path: str | Path = "findings.json") -> Path:
    """Serialize ScanResult to a pretty-printed JSON file.

    Args:
        result: The scan result to serialize.
        output_path: Where to save the JSON. Defaults to findings.json in CWD.

    Returns:
        The Path where the file was written.
    """
    output = Path(output_path)
    output.write_text(result.to_json(indent=2), encoding="utf-8")
    return output
