"""Natural-language analyzer for SKILL.md and markdown content."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

FindingType = Literal["credential_action", "prompt_injection", "social_engineering"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "nl_patterns.yaml"
WINDOW_SIZE = 3


@dataclass(frozen=True)
class NLFinding:
    """A natural-language security finding from markdown analysis."""

    file_path: str
    window_text: str
    finding_type: FindingType
    matched_terms: tuple[str, ...]
    line_number: int
    severity: Severity


@dataclass(frozen=True)
class _Sentence:
    """A sentence with its starting line number."""

    text: str
    line_number: int


def analyze_nl(content: str, file_path: str = "<string>", rules_path: Path | None = None) -> list[NLFinding]:
    """Analyze markdown text and return NL security findings."""
    rules = _load_rules(rules_path or RULES_PATH)
    sentences = _split_sentences(content)
    findings: list[NLFinding] = []

    for window in _sliding_windows(sentences, WINDOW_SIZE):
        window_text = " ".join(s.text for s in window)
        line_number = window[0].line_number
        findings.extend(_check_window(window_text, line_number, file_path, rules))

    return findings


def _load_rules(path: Path) -> dict[str, Any]:
    """Load NL pattern rules from a YAML file."""
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _split_sentences(content: str) -> list[_Sentence]:
    """Split markdown content into sentences with line numbers."""
    sentences: list[_Sentence] = []
    line_number = 1
    buffer: list[str] = []

    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            if buffer:
                sentences.append(_Sentence(" ".join(buffer), line_number))
                buffer = []
            line_number += 1
            continue

        buffer.extend(re.split(r"(?<=[.!?])\s+", stripped))
        if re.search(r"[.!?]$", stripped):
            sentences.append(_Sentence(" ".join(buffer), line_number))
            buffer = []
        line_number += 1

    if buffer:
        sentences.append(_Sentence(" ".join(buffer), line_number))

    return [s for s in sentences if s.text.strip()]


def _sliding_windows(sentences: list[_Sentence], size: int) -> list[list[_Sentence]]:
    """Return consecutive sentence windows of the given size."""
    if len(sentences) < size:
        return [sentences] if sentences else []
    return [sentences[i : i + size] for i in range(len(sentences) - size + 1)]


def _check_window(
    window_text: str,
    line_number: int,
    file_path: str,
    rules: dict[str, Any],
) -> list[NLFinding]:
    """Run all NL checks against a single text window."""
    findings: list[NLFinding] = []
    normalized = window_text.lower()

    credential = _match_credential_action(normalized, rules)
    if credential:
        findings.append(
            NLFinding(
                file_path=file_path,
                window_text=window_text,
                finding_type="credential_action",
                matched_terms=tuple(credential),
                line_number=line_number,
                severity=rules["severities"]["credential_action"],
            )
        )

    injection = _match_phrases(normalized, rules["prompt_injection_phrases"])
    if injection:
        findings.append(
            NLFinding(
                file_path=file_path,
                window_text=window_text,
                finding_type="prompt_injection",
                matched_terms=tuple(injection),
                line_number=line_number,
                severity=rules["severities"]["prompt_injection"],
            )
        )

    social = _match_phrases(normalized, rules["social_engineering_phrases"])
    if social:
        findings.append(
            NLFinding(
                file_path=file_path,
                window_text=window_text,
                finding_type="social_engineering",
                matched_terms=tuple(social),
                line_number=line_number,
                severity=rules["severities"]["social_engineering"],
            )
        )

    return findings


def _match_credential_action(normalized: str, rules: dict[str, Any]) -> list[str]:
    """Return matched credential terms and verbs when both appear in a window."""
    terms = [term for term in rules["credential_terms"] if _term_matches(normalized, term)]
    verbs = [verb for verb in rules["action_verbs"] if _word_matches(normalized, verb)]
    if terms and verbs:
        return terms + verbs
    return []


def _match_phrases(normalized: str, phrases: list[str]) -> list[str]:
    """Return phrases found as substrings in normalized text."""
    return [phrase for phrase in phrases if phrase.lower() in normalized]


def _term_matches(text: str, term: str) -> bool:
    """Match a credential term allowing space, underscore, or hyphen separators."""
    parts = term.split("_")
    pattern = r"[\s_-]?".join(re.escape(part) for part in parts)
    return re.search(rf"\b{pattern}\b", text) is not None


def _word_matches(text: str, word: str) -> bool:
    """Match a whole word in normalized text."""
    return re.search(rf"\b{re.escape(word)}\b", text) is not None
