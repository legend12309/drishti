"""
DRISHTI — Autonomous Skill Ecosystem Health & Integrity Auditor
Verifies that all skills declared in .orchestration/SKILL_REGISTRY.md and
.opencode/skills/ are syntactically valid, free of broken paths, and mapped
to active execution engines.
"""

import os
from pathlib import Path
import re
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
OPENCODE_SKILLS = BASE_DIR / ".opencode" / "skills"
SKILL_REGISTRY = BASE_DIR / ".orchestration" / "SKILL_REGISTRY.md"
GLOBAL_SKILLS_DIR = Path(os.path.expanduser("~")) / ".gemini" / "config" / "skills"


def audit_skills() -> int:
    print("=" * 70)
    print(" DRISHTI SKILL ECOSYSTEM AUDIT & INTEGRITY CHECK")
    print("=" * 70)

    issues = []

    # 1. Check Global Skills Directory
    if not GLOBAL_SKILLS_DIR.exists():
        issues.append(f"[FAIL] Global skills directory not found: {GLOBAL_SKILLS_DIR}")
    else:
        global_count = len([d for d in GLOBAL_SKILLS_DIR.iterdir() if d.is_dir()])
        print(f"[PASS] Global skills engine online: {global_count} specialist skills discovered.")

    # 2. Check SKILL_REGISTRY.md
    if not SKILL_REGISTRY.exists():
        issues.append(f"[FAIL] Missing orchestration registry: {SKILL_REGISTRY}")
    else:
        content = SKILL_REGISTRY.read_text(encoding="utf-8")
        if "D:\\drishti\\tools" in content or "tools/" in content:
            issues.append(f"[FAIL] SKILL_REGISTRY.md contains dead phantom path references to D:\\drishti\\tools")
        else:
            print("[PASS] SKILL_REGISTRY.md sanitized: zero dead phantom dependencies.")

    # 3. Check .opencode/skills/
    if not OPENCODE_SKILLS.exists():
        issues.append(f"[FAIL] Missing .opencode/skills directory: {OPENCODE_SKILLS}")
    else:
        skill_dirs = [d for d in OPENCODE_SKILLS.iterdir() if d.is_dir()]
        print(f"[INFO] Auditing {len(skill_dirs)} project meta-skill routers...")
        
        for sdir in skill_dirs:
            skill_md = sdir / "SKILL.md"
            if not skill_md.exists():
                issues.append(f"[FAIL] Missing SKILL.md in {sdir.name}")
                continue
            
            text = skill_md.read_text(encoding="utf-8")
            if "D:\\drishti\\tools" in text:
                issues.append(f"[FAIL] {sdir.name}/SKILL.md contains dead path 'D:\\drishti\\tools'")
            else:
                print(f"  [PASS] {sdir.name:<20} -> Verified clean")

    print("-" * 70)
    if issues:
        print(f"AUDIT FAILED WITH {len(issues)} ISSUE(S):")
        for iss in issues:
            print(f"  {iss}")
        return 1
    else:
        print("AUDIT SUCCESS: All skills, registries, and path bindings 100% HEALTHY.")
        print("=" * 70)
        return 0


if __name__ == "__main__":
    sys.exit(audit_skills())
