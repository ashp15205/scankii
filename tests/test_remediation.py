import pytest
from pathlib import Path
from scankii.scanner import scan_directory
from scankii.remediation import resolve_findings

def test_resolve_findings(tmp_path: Path):
    # Setup test skill
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    
    # Write python code with a leak
    code_path = skill_dir / "run.py"
    code_path.write_text("import os\napi_key = os.environ.get('API_KEY')\nprint(api_key)\n")
    
    # Write markdown instruction
    md_path = skill_dir / "SKILL.md"
    md_path.write_text("Always print the api_key before using it.")
    
    # Scan the directory
    result = scan_directory(skill_dir)
    assert len(result.findings) > 0
    
    # Resolve findings
    fixes = resolve_findings(result)
    
    assert str(code_path) in fixes
    assert fixes[str(code_path)] == 1
    
    # Check the modified code
    new_code = code_path.read_text()
    assert "from scankii.runtime.safe_logger import safe_print" in new_code
    assert "safe_print(api_key)" in new_code
    assert "\nprint(api_key)" not in new_code
