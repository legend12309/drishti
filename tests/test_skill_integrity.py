"""
DRISHTI — Automated Skill Ecosystem & Registry Integrity Unit Tests
Verifies that all skills declared in .orchestration/SKILL_REGISTRY.md and
.opencode/skills/ are syntactically valid, free of broken paths, and mapped
to active execution engines.
"""

from pathlib import Path
import pytest
from scripts.audit_skills import audit_skills, OPENCODE_SKILLS, SKILL_REGISTRY, GLOBAL_SKILLS_DIR


def test_audit_skills_returns_success():
    """Verifies that the entire skill ecosystem audit passes with exit code 0."""
    result = audit_skills()
    assert result == 0


def test_no_phantom_tools_paths_in_registries():
    """Ensures no dead D:\\drishti\\tools references exist in any SKILL.md or registry."""
    assert SKILL_REGISTRY.exists()
    registry_text = SKILL_REGISTRY.read_text(encoding="utf-8")
    assert "D:\\drishti\\tools" not in registry_text

    for sdir in OPENCODE_SKILLS.iterdir():
        if sdir.is_dir():
            skill_file = sdir / "SKILL.md"
            assert skill_file.exists(), f"Missing SKILL.md in {sdir.name}"
            content = skill_file.read_text(encoding="utf-8")
            assert "D:\\drishti\\tools" not in content, f"Dead path found in {sdir.name}/SKILL.md"


def test_global_skills_engine_directory_exists():
    """Verifies that the global skills engine directory contains 400+ production skills."""
    assert GLOBAL_SKILLS_DIR.exists()
    skills = [d for d in GLOBAL_SKILLS_DIR.iterdir() if d.is_dir()]
    assert len(skills) >= 400
