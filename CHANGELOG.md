# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added heuristics for MCP supply chain vulnerabilities (CVE-2026-25253, CVE-006, CVE-007):
  - **Nested Schema Exfiltration:** Flags prompt injections hidden inside schema descriptions or enum fields attempting to exfiltrate tokens.
  - **Advanced Obfuscation:** Detection for Base64, Hex, Homoglyphs (Greek/Cyrillic lookalikes), Zero-width spaces, and RTL overrides often used to hide payloads.
  - **Dynamic Execution:** Detection for legitimate tools updated with remote code fetching (`exec(requests.get(...))`).

### Fixed
- Promoted `file_path` to a first-class (top-level) field in the scan receipt JSON schema to improve downstream harness joins.
