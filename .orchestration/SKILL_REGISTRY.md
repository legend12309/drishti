# DRISHTI Skill Registry

## Registered Skills

| Skill | Source Path | OpenCode Path | Status | Description |
|-------|-------------|---------------|--------|-------------|
| reverse-skill | D:\drishti\tools\reverse-skill | .opencode/skills/reverse-skill/SKILL.md | ✅ Active | 80+ cybersecurity/reverse engineering modules |
| ponytail | D:\drishti\tools\ponytail | .opencode/skills/ponytail/SKILL.md | ✅ Active | 6 engineering discipline skills |
| impeccable | D:\drishti\tools\impeccable | .opencode/skills/impeccable/SKILL.md | ✅ Active | UI/UX and frontend quality |
| ecc | D:\drishti\tools\ecc | .opencode/skills/ecc/SKILL.md | ✅ Active | 200+ engineering skills |
| agent-skills | D:\drishti\tools\agent-skills | .opencode/skills/agent-skills/SKILL.md | ✅ Active | 24 software lifecycle skills |
| designer-skills | D:\drishti\tools\designer-skills | .opencode/skills/designer-skills/SKILL.md | ✅ Active | 9 product design skills |

## Skill Source Commit Hashes

| Repository | Commit Hash | Date | Branch |
|------------|-------------|------|--------|
| reverse-skill | (existing - preserved) | 2026-10-30 | main |
| ponytail | (cloned 2026-10-30) | 2026-10-30 | main |
| impeccable | (cloned 2026-10-30) | 2026-10-30 | main |
| ecc | (cloned 2026-10-30) | 2026-10-30 | main |
| agent-skills | (cloned 2026-10-30) | 2026-10-30 | main |
| designer-skills | (cloned 2026-10-30) | 2026-10-30 | main |

## Skill Routing Matrix

| Task Category | Primary Skill | Secondary Skills |
|---------------|---------------|------------------|
| Vulnerability Analysis | reverse-skill (api-security, code-audit, supply-chain-security) | ecc/security-review |
| Penetration Testing | reverse-skill (pentest-tools, attack-chain, protocol-reverse) | ecc/security-scan |
| Malware/Binary Analysis | reverse-skill (malware-analysis, ghidra-reverse, ida-reverse, radare2, pwn-chain) | |
| Scanner Integration | reverse-skill (pentest-tools) | ecc/backend-patterns, ecc/docker-patterns |
| Code Quality/Refactoring | ponytail (all), agent-skills (code-simplification, code-review-and-quality) | ecc/coding-standards |
| UI/UX Design | impeccable, designer-skills (ui-design, design-systems, interaction-design) | ecc/frontend-design-direction |
| Backend Engineering | ecc (backend-patterns, fastapi-patterns, api-design) | agent-skills (source-driven-development, incremental-implementation) |
| Frontend Engineering | ecc (frontend-patterns, react-patterns, vite-patterns), impeccable | agent-skills (frontend-ui-engineering) |
| Database Operations | ecc (database-migrations, postgres-patterns) | agent-skills (deprecation-and-migration) |
| DevOps/Docker | ecc (docker-patterns, deployment-patterns) | agent-skills (ci-cd-and-automation) |
| AI/LLM Integration | ecc (cost-aware-llm-pipeline) | agent-skills (context-engineering) |
| Testing/QA | agent-skills (test-driven-development, browser-testing-with-devtools) | ecc (e2e-testing, benchmark) |
| Product Design | designer-skills (all), impeccable | agent-skills (api-and-interface-design) |
| Documentation | agent-skills (documentation-and-adrs) | ecc (docs-governance, living-docs-governance) |
| Architecture | ecc (architecture-decision-records, orch-*) | agent-skills (planning-and-task-breakdown) |
| Security Audit | reverse-skill (code-audit, api-security, supply-chain-security), reverse-skill | ecc/security-review |
| DevOps/Infrastructure | ecc (docker-patterns, deployment-patterns) | agent-skills (ci-cd-and-automation) |

## Skill Loading Rules

1. **Orchestrator loads skills** based on task classification
2. **Minimum necessary skills** - don't load all for every task
3. **Conflict resolution** - when skills overlap, orchestrator decides
3. **Subagents receive skill context** via handoff
4. **Skills are reference-only** - source repos preserved at `D:\drishti\tools\`

## Skill Health Check

| Skill | Source Accessible | OpenCode Compatible | Last Verified |
|-------|-------------------|---------------------|---------------|
| reverse-skill | ✅ | ✅ (native router) | 2026-10-30 |
| ponytail | ✅ | ✅ (native .opencode) | 2026-10-30 |
| impeccable | ✅ | ✅ (native .opencode) | 2026-10-30 |
| ecc | ✅ | ✅ (native .opencode) | 2026-10-30 |
| agent-skills | ✅ | ✅ (native .opencode) | 2026-10-30 |
| designer-skills | ✅ | ✅ (references) | 2026-10-30 |