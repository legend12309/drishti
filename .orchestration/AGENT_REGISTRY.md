# DRISHTI Agent Registry

## Primary Agent

| Agent | Mode | Path | Description |
|-------|------|------|-------------|
| drishti-orchestrator | primary | .opencode/agents/drishti-orchestrator.md | Master Orchestrator - coordinates all work |

## Specialist Subagents

| Agent | Mode | Path | Responsibility | Permissions |
|-------|------|------|----------------|-------------|
| principal-architect | subagent | .opencode/agents/principal-architect.md | Architecture decisions, system integration, technical strategy | read, write, edit, bash |
| security-auditor | subagent | .opencode/agents/security-auditor.md | Security review, vulnerability findings, authorization enforcement | read, bash |
| backend-engineer | subagent | .opencode/agents/backend-engineer.md | FastAPI, Python services, scanner adapters, orchestrator | read, write, edit, bash |
| frontend-engineer | subagent | .opencode/agents/frontend-engineer.md | React, Vite, TypeScript, UI state, API integration | read, write, edit, bash |
| database-reviewer | subagent | .opencode/agents/database-reviewer.md | PostgreSQL schema, migrations, RLS, query performance | read, bash |
| devops-engineer | subagent | .opencode/agents/devops-engineer.md | Docker, runtime deps, container orchestration, CI/CD | read, write, edit, bash |
| ai-engineer | subagent | .opencode/agents/ai-engineer.md | LLM providers, routing, fallback, prompt engineering | read, write, edit, bash |
| product-designer | subagent | .opencode/agents/product-designer.md | UX strategy, interaction design, design systems | read, write, edit, bash |
| qa-reviewer | subagent | .opencode/agents/qa-reviewer.md | Unit, integration, regression, security tests | read, write, edit, bash |
| documentation-writer | subagent | .opencode/agents/documentation-writer.md | Technical docs, project state, architecture decisions | read, write, edit, bash |

## Agent Capability Matrix

| Capability | principal-architect | security-auditor | backend-engineer | frontend-engineer | database-reviewer | devops-engineer | ai-engineer | product-designer | qa-reviewer | documentation-writer |
|------------|---------------------|------------------|------------------|-------------------|-------------------|-----------------|-------------|------------------|-------------|---------------------|
| Architecture Decisions | ✅ | | | | | | | | | |
| Security Review | | ✅ | | | | | | | | |
| FastAPI Implementation | | | ✅ | | | | | | | |
| React/TypeScript | | | | ✅ | | | | | | |
| Database Schema | | | | | ✅ | | | | | |
| Docker/Infrastructure | | | | | | ✅ | | | | |
| LLM Providers/Routing | | | | | | | ✅ | | | |
| UX/Design Systems | | | | | | | | ✅ | | |
| Test Execution | | | | | | | | | ✅ | |
| Documentation | | | | | | | | | | ✅ |

## Skill Assignments

| Agent | Primary Skills | Secondary Skills |
|-------|----------------|------------------|
| principal-architect | ecc/agent-architecture-audit, ecc/orch-* | ecc/architecture-decision-records |
| security-auditor | reverse-skill (code-audit, api-security, supply-chain-security), ecc/security-review | ecc/security-scan |
| backend-engineer | ecc/fastapi-patterns, ecc/backend-patterns, ecc/python-patterns | ecc/api-design, agent-skills/test-driven-development |
| frontend-engineer | ecc/frontend-patterns, ecc/react-patterns, ecc/vite-patterns, impeccable | ecc/frontend-a11y, agent-skills/frontend-ui-engineering |
| database-reviewer | ecc/database-migrations, ecc/postgres-patterns | ecc/prisma-patterns |
| devops-engineer | ecc/docker-patterns, ecc/deployment-patterns, ecc/kubernetes-patterns | ecc/observability-and-instrumentation |
| ai-engineer | ecc/cost-aware-llm-pipeline, ecc/foundation-models-on-device | ecc/llm-trading-agent-security |
| product-designer | designer-skills (all), impeccable | ecc/frontend-design-direction |
| qa-reviewer | agent-skills/test-driven-development, agent-skills/browser-testing-with-devtools | ecc/e2e-testing, ecc/benchmark |
| documentation-writer | agent-skills/documentation-and-adrs, ecc/docs-governance | ecc/living-docs-governance |

## Invocation Rules

1. **Orchestrator only** can invoke subagents
2. **Subagents cannot invoke other subagents**
3. **File ownership** must be declared before modification
4. **Handoffs required** for all completed work
5. **Reviews required** for all significant changes