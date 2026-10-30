# DRISHTI File Ownership Registry

## Ownership Rules
1. **Single owner per file** - only assigned agent may modify
2. **Ownership declared** before any modification
3. **Conflicts resolved** by orchestrator before parallel work
4. **Shared files** require explicit coordination

## Backend Files

| File | Owner | Shared With | Notes |
|------|-------|-------------|-------|
| Dockerfile | devops-engineer | backend-engineer | WeasyPrint deps |
| backend/main.py | backend-engineer | devops-engineer | SPA route fix |
| backend/api/scans.py | backend-engineer | | Report endpoints |
| backend/api/auth.py | backend-engineer | | Auth endpoints |
| backend/api/authorizations.py | backend-engineer | security-auditor | Auth logic |
| backend/api/vulnerabilities.py | backend-engineer | | CVE endpoints |
| backend/api/graph.py | backend-engineer | ai-engineer | Graph endpoints |
| backend/api/llm.py | ai-engineer | backend-engineer | LLM routing |
| backend/services/report_generator.py | backend-engineer | | PDF generation |
| backend/services/scan_orchestrator.py | backend-engineer | | Orchestration logic |
| backend/services/nmap_adapter.py | backend-engineer | security-auditor | Nmap integration |
| backend/services/zap_adapter.py | backend-engineer | security-auditor | ZAP integration |
| backend/services/nuclei_adapter.py | backend-engineer | | Nuclei integration |
| backend/services/trivy_adapter.py | backend-engineer | | Trivy integration |
| backend/services/httpx_adapter.py | backend-engineer | | HTTPX integration |
| backend/services/authorizations.py | backend-engineer | security-auditor | Auth logic |
| backend/services/authorizations.py | backend-engineer | | Auth validation |
| backend/services/scope.py | backend-engineer | security-auditor | Scope validation |
| backend/db/database.py | backend-engineer | database-reviewer | DB abstraction |
| backend/db/migrations/*.sql | database-reviewer | backend-engineer | Applied by reviewer |

## Frontend Files

| File | Owner | Shared With | Notes |
|------|-------|-------------|-------|
| frontend/src/views/ReportsView.tsx | frontend-engineer | product-designer | New component |
| frontend/src/views/ReconView.tsx | frontend-engineer | | Main recon view |
| frontend/src/views/DashboardView.tsx | frontend-engineer | product-designer | Dashboard |
| frontend/src/views/*.tsx | frontend-engineer | | Other views |
| frontend/src/components/Sidebar.tsx | frontend-engineer | | Navigation |
| frontend/src/components/*.tsx | frontend-engineer | | UI components |
| frontend/src/types.ts | frontend-engineer | | Type definitions |
| frontend/src/App.tsx | frontend-engineer | | Main app |
| frontend/src/main.tsx | frontend-engineer | | Entry point |
| frontend/vite.config.ts | frontend-engineer | devops-engineer | Build config |
| frontend/package.json | frontend-engineer | devops-engineer | Dependencies |
| frontend/tailwind.config.js | product-designer | frontend-engineer | Design tokens |

## Configuration Files

| File | Owner | Notes |
|------|-------|-------|
| docker-compose.yml | devops-engineer | Service definitions |
| .env | devops-engineer | Secrets (not committed) |
| .env.example | devops-engineer | Template |
| requirements.txt | backend-engineer | Python deps |
| opencode.jsonc | principal-architect | Orchestration config |
| AGENTS.md | principal-architect | Agent instructions |

## Documentation Files

| File | Owner | Notes |
|------|-------|-------|
| docs/project-audit/CURRENT_STATE.md | documentation-writer | Current state |
| docs/UNIFIED_RECON_REPAIR_REPORT.md | documentation-writer | Repair log |
| docs/UNIFIED_RECON_TEST_MATRIX.md | documentation-writer | Test matrix |
| docs/BUGS_AND_ISSUES_REPORT.md | documentation-writer | Bug register |
| docs/ai-orchestration/*.md | documentation-writer | Orchestration docs |

## Orchestration Files

| File | Owner | Notes |
|------|-------|-------|
| .orchestration/PROJECT_CONTEXT.md | principal-architect | Project state |
| .orchestration/GLOBAL_REQUIREMENTS.md | principal-architect | Requirements |
| .orchestration/TASK_REGISTRY.md | principal-architect | Task tracking |
| .orchestration/DEPENDENCY_GRAPH.md | principal-architect | Dependencies |
| .orchestration/AGENT_REGISTRY.md | principal-architect | Agent catalog |
| .orchestration/SKILL_REGISTRY.md | principal-architect | Skills catalog |
| .orchestration/FILE_OWNERSHIP.md | principal-architect | This file |
| .orchestration/ARCHITECTURE_DECISIONS.md | principal-architect | ADRs |
| .orchestration/DECISION_LOG.md | principal-architect | Decisions |
| .orchestration/INTEGRATION_STATUS.md | principal-architect | Integration tracking |
| .orchestration/QUALITY_GATE_RESULTS.md | qa-reviewer | Test results |

## Ownership Conflict Resolution

1. **Declare intent** in task handoff before modifying
2. **Orchestrator arbitrates** simultaneous requests
3. **Serial execution** for conflicting files
4. **Git worktrees** if available for parallel work