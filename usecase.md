# Developer Use Cases for scankii

This document explains why individual developers need `scankii` and how to fit it into your workflow.

## 1. What is an AI Agent Skill, and why does it need scanning?

When you build an AI Agent (using frameworks like LangChain, AutoGen, or OpenAI Functions), you give the AI "skills" or "tools" so it can interact with the real world. A skill usually has two parts:
1. **The Code**: A Python or Node script (e.g., `search_database.py`) that actually does the work.
2. **The Prompt**: A Markdown file (e.g., `SKILL.md`) containing English instructions that tell the AI *how* to use your code.

Traditional security tools only scan your code. But what if your English instructions accidentally tell the AI to print your database password for debugging? The AI runs the code, prints the password, captures the output, and now the AI itself (and potentially the user chatting with it) knows your password. 

This is called a **Cross-Modal Leak**. `scankii` is an open-source tool designed to read both your code and your English instructions to find these leaks before they happen.

## 2. When should I use scankii?

You can integrate `scankii` at any stage of development:
*   **Locally:** Run `scankii scan ./my-skill/` in your terminal before you push code to GitHub.
*   **Automatically:** Use our pre-commit hook to automatically scan every time you type `git commit`.
*   **In the Cloud:** Add `scankii` to your GitHub Actions to block Pull Requests that contain hidden leaks.

## 3. How to use scankii

### Scenario A: Building a New Skill
When you start a new AI skill, use our secure template so you don't accidentally introduce leaks.
1. **Copy the template:**
   ```bash
   cp templates/SKILL.md.template my-new-skill/SKILL.md
   ```
2. **Write your code:** Make sure you load API keys from environment variables (like `os.environ.get('API_KEY')`), rather than passing them through the AI.
3. **Scan it:**
   ```bash
   scankii scan ./my-new-skill/ --explain
   ```
   If you accidentally created a leak, the `--explain` flag will draw a diagram showing exactly how the secret gets from your English instructions out to the internet.

### Scenario B: Auditing a Community Skill
If you download an open-source AI skill from GitHub, you shouldn't trust it blindly.
1. **Scan the downloaded folder:**
   ```bash
   scankii scan ./downloaded-skill/
   ```
2. **Review the table:** `scankii` will list any CRITICAL or HIGH severity issues.
3. **Fix it:** `scankii` will suggest exactly how to rewrite the code or the Markdown to fix the vulnerability.

### Scenario C: Securing Debug Logs with `scankii.runtime`
Sometimes your code *has* to print debugging info, but you don't want the AI to read the sensitive parts. We include a tool for this directly built into the package!
1. **Install:**
   ```bash
   pip install scankii
   ```
2. **Use it instead of `print()`:**
   ```python
   from scankii.runtime.safe_logger import safe_print
   import os

   api_key = os.environ.get('API_KEY')
   safe_print(f"Using token: {api_key}") 
   # Actually outputs: Using token: sk-[REDACTED]
   ```
   Because it is redacted, the AI never sees the real key.

## 4. Why scankii over GitLeaks or TruffleHog?

Tools like GitLeaks are amazing, but they are looking for strings like `password="12345"` hardcoded in your Python file. 
If your code is perfectly secure, but your English prompt tells the AI to expose the secret, GitLeaks will say you are 100% secure. `scankii` understands how AI agents actually work and stops these modern prompt-driven leaks.
