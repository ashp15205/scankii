"""Auto-remediation engine for scankii findings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scankii.scanner import ScanResult
from scankii.core.ast_analyzer import ASTFinding


def resolve_findings(result: ScanResult) -> dict[str, int]:
    """Auto-resolve findings that can be safely fixed.

    Currently supports replacing `print` with `safe_print` in Python files.
    Returns a dict mapping file_path to the number of fixes applied.
    """
    # 1. Collect all ASTFindings (direct or nested in CrossModalFinding)
    ast_findings: list[ASTFinding] = []
    for sf in result.findings:
        finding = sf.finding
        if isinstance(finding, ASTFinding):
            ast_findings.append(finding)
        elif hasattr(finding, "ast_finding") and getattr(finding, "ast_finding") is not None:
            # It's a CrossModalFinding
            ast_findings.append(getattr(finding, "ast_finding"))

    # 2. Group by file_path
    findings_by_file: dict[str, list[ASTFinding]] = {}
    for f in ast_findings:
        if f.file_path.endswith(".py") and f.sink_name == "Python print()":
            findings_by_file.setdefault(f.file_path, []).append(f)

    # 3. Apply fixes file by file
    fixes_applied: dict[str, int] = {}
    
    for file_path, findings in findings_by_file.items():
        path = Path(file_path)
        if not path.is_file():
            continue
            
        # Read raw bytes so we can index accurately using tree-sitter byte offsets
        content_bytes = path.read_bytes()
        
        # Sort findings by start_byte DESCENDING
        # This is critical so that replacing bytes at the end of the file doesn't
        # shift the byte offsets for findings earlier in the file.
        # We also deduplicate by start_byte just in case.
        unique_findings = {f.start_byte: f for f in findings}.values()
        sorted_findings = sorted(unique_findings, key=lambda f: f.start_byte, reverse=True)
        
        fixes_in_file = 0
        for f in sorted_findings:
            if f.start_byte == 0 and f.end_byte == 0:
                continue # Missing byte offsets (legacy JSON load)
                
            # Double check the bytes we are replacing actually say "print"
            target_slice = content_bytes[f.start_byte:f.end_byte].decode("utf-8")
            if target_slice == "print":
                # Replace exactly those bytes with "safe_print"
                content_bytes = content_bytes[:f.start_byte] + b"safe_print" + content_bytes[f.end_byte:]
                fixes_in_file += 1
                
        if fixes_in_file > 0:
            content_str = content_bytes.decode("utf-8")
            # Inject import statement if missing
            import_stmt = "from scankii.runtime.safe_logger import safe_print\n"
            if import_stmt.strip() not in content_str:
                content_str = import_stmt + content_str
                
            path.write_text(content_str, encoding="utf-8")
            fixes_applied[str(file_path)] = fixes_in_file

    return fixes_applied
