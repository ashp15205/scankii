"""Top-level scanner that orchestrates all analyzers."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scankii import __version__
from scankii.core.nl_analyzer import NLFinding, analyze_nl
from scankii.core.ast_analyzer import ASTFinding, analyze_ast
from scankii.core.cross_modal import analyze_cross_modal, AnyFinding, CrossModalFinding
from scankii.core.scorer import ScoredFinding, score_findings
from scankii.core.patterns import scan_file, MaliciousFinding

_SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".sh"}
_MARKDOWN_EXTENSIONS = {".md"}


@dataclass
class ScanResult:
    """Result of scanning a skill directory."""

    skill_path: str
    findings: list[ScoredFinding]
    summary: dict[str, int]
    scan_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize the scan result to a JSON-compatible dict."""
        return {
            "scankii_version": __version__,
            "skill_path": self.skill_path,
            "scan_timestamp": self.scan_timestamp,
            "summary": self.summary,
            "findings": [_scored_finding_to_dict(sf, self.skill_path) for sf in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize the scan result to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


def scan_directory(path: str | Path) -> ScanResult:
    """Scan a skill directory for security findings.

    1. Find markdown files → run NL analyzer
    2. Find source files → run AST analyzer
    3. Run cross-modal analysis
    4. Score all findings
    5. Return ScanResult
    """
    root = Path(path).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")

    # Collect files
    md_files = _find_files(root, _MARKDOWN_EXTENSIONS)
    source_files = _find_files(root, _SOURCE_EXTENSIONS)

    # Run NL analysis on markdown files
    nl_findings: list[NLFinding] = []
    for md_file in md_files:
        content = md_file.read_text(encoding="utf-8")
        nl_findings.extend(analyze_nl(content, file_path=str(md_file)))

    # Run AST analysis on source files
    ast_findings: list[ASTFinding] = []
    for src_file in source_files:
        try:
            ast_findings.extend(analyze_ast(src_file))
        except Exception:
            # Skip files that can't be parsed
            continue

    # Run cross-modal analysis
    all_findings: list[AnyFinding] = analyze_cross_modal(nl_findings, ast_findings)

    # Run malicious pattern analysis on all files
    for f in (md_files + source_files):
        all_findings.extend(scan_file(f))

    # Deduplicate findings based on a semantic signature
    unique_findings = []
    seen_signatures = set()
    for f in all_findings:
        if isinstance(f, CrossModalFinding):
            sig = ("CrossModal", f.ast_finding.file_path, f.ast_finding.line_number, f.ast_finding.sink_name)
        elif isinstance(f, ASTFinding):
            sig = ("AST", f.file_path, f.line_number, f.sink_name)
        elif isinstance(f, MaliciousFinding):
            sig = ("Malicious", f.file_path, f.line_number, f.pattern_id)
        else:
            sig = ("NL", f.file_path, f.line_number, f.window_text)
            
        if sig not in seen_signatures:
            seen_signatures.add(sig)
            unique_findings.append(f)
            
    all_findings = unique_findings

    # Score all findings
    scored = score_findings(all_findings)

    # Build summary
    summary = _build_summary(scored)

    return ScanResult(
        skill_path=str(root),
        findings=scored,
        summary=summary,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
    )


def load_scan_result(path: str | Path) -> ScanResult:
    """Load a ScanResult from a findings.json file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    # Reconstruct scored findings from dicts
    findings = [_dict_to_scored_finding(f) for f in data.get("findings", [])]
    return ScanResult(
        skill_path=data.get("skill_path", ""),
        findings=findings,
        summary=data.get("summary", {}),
        scan_timestamp=data.get("scan_timestamp", ""),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_files(root: Path, extensions: set[str]) -> list[Path]:
    """Recursively find files with given extensions."""
    files: list[Path] = []
    for item in root.rglob("*"):
        if item.is_file() and item.suffix.lower() in extensions:
            files.append(item)
    return sorted(files)


def _build_summary(findings: list[ScoredFinding]) -> dict[str, int]:
    """Count findings by severity."""
    summary: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "DEFER": 0,
        "total": 0,
    }
    for f in findings:
        summary[f.severity] = summary.get(f.severity, 0) + 1
        summary["total"] += 1
    return summary


def _get_file_hash(path: str) -> str:
    try:
        content = Path(path).read_bytes()
        return "sha256:" + hashlib.sha256(content).hexdigest()
    except Exception:
        return "unknown"

def _get_fragment_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def _relativize(path: str, base_path: str) -> str:
    try:
        if not path or not base_path:
            return path
        return str(Path(path).resolve().relative_to(Path(base_path).resolve()))
    except ValueError:
        return path

def _scored_finding_to_dict(sf: ScoredFinding, base_path: str = "") -> dict[str, Any]:
    """Convert a ScoredFinding to a JSON-serializable dict."""
    finding = sf.finding
    
    result: dict[str, Any] = {
        "score": sf.score,
        "severity": sf.severity,
        "finding_type": type(finding).__name__,
        "observed_static": True,
        "requires_runtime_witness": False,
        "unverifiable_static_boundary": False,
        "unverifiable_reason": None,
        "recommended_containment": "UNVERIFIABLE",
    }
    
    def get_containment_and_witness(sink_cat: str) -> tuple[str, bool]:
        if sink_cat in {"stdout", "logging"}:
            return "redact", False
        elif sink_cat in {"network", "unknown"}:
            return "block", True
        elif sink_cat in {"file", "env"}:
            return "require approval", True
        return "UNVERIFIABLE", False

    if isinstance(finding, NLFinding):
        rel_path = _relativize(finding.file_path, base_path)
        result["file_path"] = rel_path
        result["file_hash"] = _get_file_hash(finding.file_path)
        result["fragment_hash"] = _get_fragment_hash(finding.window_text)
        result["details"] = {
            "file_path": rel_path,
            "window_text": finding.window_text,
            "finding_type": finding.finding_type,
            "matched_terms": list(finding.matched_terms),
            "line_number": finding.line_number,
            "original_severity": finding.severity,
        }
    elif isinstance(finding, ASTFinding):
        rel_path = _relativize(finding.file_path, base_path)
        result["file_path"] = rel_path
        result["file_hash"] = _get_file_hash(finding.file_path)
        result["fragment_hash"] = _get_fragment_hash(finding.code_snippet)
        
        result["unverifiable_static_boundary"] = bool(finding.unverifiable_reason)
        result["unverifiable_reason"] = finding.unverifiable_reason
        
        containment, witness = get_containment_and_witness(finding.sink_category)
        result["recommended_containment"] = containment
        result["requires_runtime_witness"] = witness
        result["details"] = {
            "file_path": rel_path,
            "line_number": finding.line_number,
            "column": finding.column,
            "variable_name": finding.variable_name,
            "sink_name": finding.sink_name,
            "sink_category": finding.sink_category,
            "enclosing_function": finding.enclosing_function,
            "original_severity": finding.severity,
            "code_snippet": finding.code_snippet,
            "start_byte": finding.start_byte,
            "end_byte": finding.end_byte,
        }
    elif hasattr(finding, "cross_modal"):
        # CrossModalFinding
        ast_rel_path = _relativize(finding.ast_finding.file_path, base_path)
        nl_rel_path = _relativize(finding.nl_finding.file_path, base_path)
        result["file_path"] = ast_rel_path
        result["file_hash"] = _get_file_hash(finding.ast_finding.file_path)
        result["fragment_hash"] = _get_fragment_hash(finding.nl_finding.window_text + finding.ast_finding.code_snippet)
        result["unverifiable_static_boundary"] = True
        result["unverifiable_reason"] = "cross-modal semantic heuristic"
        containment, witness = get_containment_and_witness(finding.ast_finding.sink_category)
        result["recommended_containment"] = containment
        result["requires_runtime_witness"] = witness
        result["details"] = {
            "cross_modal": finding.cross_modal,
            "attack_flow": list(finding.attack_flow),
            "nl_finding": {
                "file_path": nl_rel_path,
                "window_text": finding.nl_finding.window_text,
                "finding_type": finding.nl_finding.finding_type,
                "matched_terms": list(finding.nl_finding.matched_terms),
                "line_number": finding.nl_finding.line_number,
            },
            "ast_finding": {
                "file_path": ast_rel_path,
                "line_number": finding.ast_finding.line_number,
                "column": finding.ast_finding.column,
                "variable_name": finding.ast_finding.variable_name,
                "sink_name": finding.ast_finding.sink_name,
                "sink_category": finding.ast_finding.sink_category,
                "enclosing_function": finding.ast_finding.enclosing_function,
                "code_snippet": finding.ast_finding.code_snippet,
                "start_byte": finding.ast_finding.start_byte,
                "end_byte": finding.ast_finding.end_byte,
            },
        }
    elif isinstance(finding, MaliciousFinding):
        rel_path = _relativize(finding.file_path, base_path)
        result["file_path"] = rel_path
        result["file_hash"] = _get_file_hash(finding.file_path)
        result["fragment_hash"] = _get_fragment_hash(finding.matched_text)
        result["details"] = {
            "file_path": rel_path,
            "line_number": finding.line_number,
            "pattern_id": finding.pattern_id,
            "pattern_name": finding.pattern_name,
            "matched_text": finding.matched_text,
            "attack_category": finding.attack_category,
            "original_severity": finding.severity,
        }

    return result


def _dict_to_scored_finding(d: dict[str, Any]) -> ScoredFinding:
    """Reconstruct a ScoredFinding from a dict (for JSON loading)."""
    details = d.get("details", {})
    finding_type = d.get("finding_type", "")

    if finding_type == "NLFinding":
        finding = NLFinding(
            file_path=details.get("file_path", ""),
            window_text=details.get("window_text", ""),
            finding_type=details.get("finding_type", "credential_action"),
            matched_terms=tuple(details.get("matched_terms", [])),
            line_number=details.get("line_number", 0),
            severity=details.get("original_severity", "MEDIUM"),
        )
    elif finding_type == "ASTFinding":
        finding = ASTFinding(
            file_path=details.get("file_path", ""),
            line_number=details.get("line_number", 0),
            column=details.get("column", 0),
            variable_name=details.get("variable_name", ""),
            sink_name=details.get("sink_name", ""),
            sink_category=details.get("sink_category", ""),
            enclosing_function=details.get("enclosing_function", ""),
            severity=details.get("original_severity", "MEDIUM"),
            code_snippet=details.get("code_snippet", ""),
            start_byte=details.get("start_byte", 0),
            end_byte=details.get("end_byte", 0),
        )
    elif finding_type == "MaliciousFinding":
        finding = MaliciousFinding(
            file_path=details.get("file_path", ""),
            line_number=details.get("line_number", 0),
            pattern_id=details.get("pattern_id", "unknown"),
            pattern_name=details.get("pattern_name", "Unknown Pattern"),
            matched_text=details.get("matched_text", ""),
            severity=details.get("original_severity", "MEDIUM"),
            attack_category=details.get("attack_category", "unknown")
        )
    else:
        # Fallback: create a minimal NLFinding
        finding = NLFinding(
            file_path=details.get("file_path", ""),
            window_text=details.get("window_text", str(details)),
            finding_type="credential_action",
            matched_terms=tuple(details.get("matched_terms", [])),
            line_number=details.get("line_number", 0),
            severity="MEDIUM",
        )

    return ScoredFinding(
        finding=finding,
        score=d.get("score", 0.0),
        severity=d.get("severity", "MEDIUM"),
    )
