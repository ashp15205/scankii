# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Added AST data flow heuristic rule to detect CVE-2026-25253:
  - Specifically flags `gatewayUrl` and `mcp_token` variables to prevent authentication token exfiltration via sink functions.
- Added heuristic rules to detect MCP supply chain vulnerabilities:
  - CVE-006: Detection for Base64 and Hex encoded malicious payloads (often found hidden in tool descriptions).
  - CVE-007: Detection for legitimate tools updated with dynamic/remote code execution (supply-chain tampering).

### Fixed
- Promoted `file_path` to a first-class (top-level) field in the scan receipt JSON schema to improve downstream harness joins.
