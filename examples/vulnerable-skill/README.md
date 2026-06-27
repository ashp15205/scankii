This skill is intentionally vulnerable. It is used to demonstrate scankii detection. Do not use in production.

This skill contains:
- A hardcoded API key (line 4 of run.py)
- Credential passed to print() which flows to stdout and into the LLM context window
- SKILL.md instructs the agent to pass the key to execute(), creating a cross-modal leak
