# /orchestrate Command

Orchestrate a complex multi-agent task with automatic skill selection, agent delegation, and integration.

## Usage
```
/orchestrate <objective>
```

## Behavior

1. **Parse Objective** - Analyze the user's request to understand scope
2. **Classify Task** - Map to task categories (security, backend, frontend, database, etc.)
3. **Select Skills** - Load relevant skills from registry based on classification
4. **Create Task Plan** - Decompose into subtasks with dependencies
5. **Assign Agents** - Map subtasks to specialist agents with file ownership
6. **Execute** - Delegate to subagents via Task tool with full context
7. **Monitor** - Track progress, detect conflicts, manage dependencies
8. **Review** - Request independent reviews for significant changes
9. **Integrate** - Merge completed work, resolve conflicts
10. **Verify** - Run relevant tests, validate acceptance criteria
11. **Document** - Update project state, task registry, decision log

## Task Classification Rules

| Keywords | Category | Primary Skills | Primary Agent |
|----------|----------|----------------|---------------|
| vulnerability, scanner, exploit, malware, reverse, pentest | security | reverse-skill, ecc/security-* | security-auditor, backend-engineer |
| API, endpoint, FastAPI, backend, scanner, orchestrator | backend | ecc/backend-patterns, ecc/fastapi-patterns | backend-engineer |
| React, TypeScript, UI, dashboard, frontend, component | frontend | ecc/frontend-*, impeccable, designer-skills | frontend-engineer, product-designer |
| database, migration, schema, RLS, query, PostgreSQL | database | ecc/database-*, ecc/postgres-patterns | database-reviewer |
| Docker, container, CI/CD, deploy, infrastructure | devops | ecc/docker-*, ecc/deployment-* | devops-engineer |
| LLM, AI, prompt, Gemini, Groq, NVIDIA, HuggingFace | ai | ecc/cost-aware-llm-pipeline | ai-engineer |
| design, UX, UI, accessibility, design system | design | impeccable, designer-skills | product-designer |
| test, QA, regression, security test | qa | agent-skills/test-*, ecc/e2e-testing | qa-reviewer |
| documentation, ADR, decision, architecture doc | docs | agent-skills/documentation-*, ecc/docs-* | documentation-writer |
| architecture, integration, decision, strategy | architecture | ecc/architecture-*, agent-skills/planning-* | principal-architect |

## Example Usage
```
/orchestrate "Add vulnerability correlation to PDF reports with severity charts"
/orchestrate "Fix Nmap timeout enforcement in monitor loop"
/orchestrate "Redesign ReportsView with better data visualization"
/orchestrate "Add database migration for scan_reports table"
/orchestrate "Create fresh DNS TXT challenge for curezy.in"
```

## Output
Returns structured task plan with:
- Task ID and subtasks
- Agent assignments
- File ownership
- Dependencies
- Acceptance criteria
- Estimated timeline