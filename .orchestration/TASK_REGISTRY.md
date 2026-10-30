# DRISHTI Task Registry

## Task Format
| Field | Description |
|-------|-------------|
| ID | Unique task identifier |
| Objective | What needs to be accomplished |
| Priority | P0 (blocking), P1 (critical), P2 (important), P3 (nice-to-have) |
| Assigned Agent | Primary agent responsible |
| Supporting Skills | Skills required |
| Dependencies | Task IDs that must complete first |
| Files Owned | Files this task modifies |
| Acceptance Criteria | Measurable completion criteria |
| State | BACKLOG, READY, IN_PROGRESS, BLOCKED, WAITING_FOR_REVIEW, INTEGRATION, COMPLETED, FAILED, CANCELLED |
| Deliverables | Tangible outputs |
| Test Results | Test outcomes |
| Review Status | PENDING, IN_REVIEW, APPROVED, CHANGES_REQUESTED |

## Current Tasks

### T-001: Docker WeasyPrint Fix
- **Objective**: Fix PDF generation in Docker by installing required GTK libraries
- **Priority**: P0
- **Assigned Agent**: devops-engineer
- **Supporting Skills**: ecc/docker-patterns
- **Dependencies**: None
- **Files Owned**: Dockerfile
- **Acceptance Criteria**: `docker run --rm drishti-drishti python -c "from weasyprint import HTML, CSS; print('WeasyPrint works!')"` succeeds
- **State**: COMPLETED
- **Deliverables**: Fixed Dockerfile with libpangoft2-1.0-0 from Debian unstable
- **Test Results**: ✅ "WeasyPrint works!" verified
- **Review Status**: APPROVED

### T-002: Frontend ReportsView Implementation
- **Objective**: Create complete ReportsView component with navigation integration
- **Priority**: P0
- **Assigned Agent**: frontend-engineer
- **Supporting Skills**: ecc/frontend-patterns, ecc/react-patterns, impeccable
- **Dependencies**: T-001
- **Files Owned**: frontend/src/views/ReportsView.tsx, frontend/src/components/Sidebar.tsx, frontend/src/types.ts
- **Acceptance Criteria**: 
  - `/reports` route accessible
  - Reports table with real API data
  - Download/Regenerate actions work
  - Loading/Empty/Error states
  - Navigation in Sidebar
  - TypeScript clean build
- **State**: COMPLETED
- **Deliverables**: ReportsView.tsx, Sidebar.tsx update, types.ts update
- **Test Results**: ✅ Frontend build passes, TypeScript clean
- **Review Status**: APPROVED

### T-003: Backend Report Endpoints
- **Objective**: Ensure report generation and download endpoints work
- **Priority**: P0
- **Assigned Agent**: backend-engineer
- **Supporting Skills**: ecc/fastapi-patterns, ecc/backend-patterns
- **Dependencies**: T-001
- **Files Owned**: backend/api/scans.py, backend/services/report_generator.py
- **Acceptance Criteria**:
  - POST /orchestrator/workflows/{id}/report generates PDF
  - GET /orchestrator/workflows/{id}/report/download returns PDF binary
  - GET /orchestrator/workflows lists workflows for ReportsView
- **State**: COMPLETED
- **Deliverables**: Fixed report_generator.py, added list_workflows endpoint
- **Test Results**: ✅ 122/122 tests pass, manual API test passes
- **Review Status**: APPROVED

### T-004: Scan Reports Database Migration
- **Objective**: Apply missing scan_reports table migration
- **Priority**: P0
- **Assigned Agent**: database-reviewer
- **Supporting Skills**: ecc/database-migrations, ecc/postgres-patterns
- **Dependencies**: T-001
- **Files Owned**: data/migrations/010_scan_reports.sql
- **Acceptance Criteria**: scan_reports table exists with proper schema
- **State**: COMPLETED
- **Deliverables**: Applied migration 010
- **Test Results**: ✅ Table verified in PostgreSQL
- **Review Status**: APPROVED

### T-005: SPA Route Fix for API Paths
- **Objective**: Fix SPA catch-all route to exclude /api/* paths
- **Priority**: P0
- **Assigned Agent**: backend-engineer
- **Supporting Skills**: ecc/fastapi-patterns
- **Dependencies**: T-002
- **Files Owned**: backend/main.py
- **Acceptance Criteria**: API routes return JSON, not HTML
- **State**: COMPLETED
- **Deliverables**: Fixed serve_spa route with regex exclusion
- **Test Results**: ✅ API endpoints return JSON
- **Review Status**: APPROVED

### T-005: curezy.in DNS Authorization
- **Objective**: Create fresh DNS TXT challenge for curezy.in
- **Priority**: P1
- **Assigned Agent**: backend-engineer
- **Supporting Skills**: reverse-skill (pentest-tools/recon-pipeline)
- **Dependencies**: None
- **Files Owned**: None (operational)
- **Acceptance Criteria**: 
  - Valid authorization created for curezy.in
  - DNS TXT record propagated
  - Challenge verified via API
- **State**: BLOCKED (all existing authorizations expired)
- **Review Status**: PENDING

### T-006: End-to-End PDF Delivery Test
- **Objective**: Verify complete PDF generation → download → open flow
- **Priority**: P1
- **Assigned Agent**: qa-reviewer
- **Supporting Skills**: agent-skills/test-driven-development, agent-skills/browser-testing-with-devtools
- **Dependencies**: T-001, T-002, T-003
- **Files Owned**: Test artifacts
- **Acceptance Criteria**:
  - Generate report from persisted scan
  - Report listed in ReportsView
  - Download via frontend works
  - Downloaded PDF opens and matches source data
- **State**: COMPLETED (verified with test.local sandbox target)
- **Test Results**: ✅ 21KB PDF generated, downloaded, verified
- **Review Status**: APPROVED

### T-007: Git Repository Initialization
- **Objective**: Initialize git repository and commit all changes
- **Priority**: P2
- **Assigned Agent**: devops-engineer
- **Supporting Skills**: ecc/git-workflow, agent-skills/git-workflow-and-versioning
- **Dependencies**: All P0 tasks
- **Files Owned**: .git/, all modified files
- **Acceptance Criteria**: 
  - git init
  - .gitignore configured
  - All changes committed with proper messages
  - Branch created
- **State**: READY
- **Review Status**: PENDING

### T-008: Documentation Update
- **Objective**: Update all project documentation with current state
- **Priority**: P1
- **Assigned Agent**: documentation-writer
- **Supporting Skills**: agent-skills/documentation-and-adrs, ecc/docs-governance
- **Dependencies**: All P0 tasks
- **Files Owned**: docs/project-audit/CURRENT_STATE.md, docs/UNIFIED_RECON_REPAIR_REPORT.md, docs/UNIFIED_RECON_TEST_MATRIX.md, docs/BUGS_AND_ISSUES_REPORT.md
- **Acceptance Criteria**: All docs reflect current verified state
- **State**: IN_PROGRESS
- **Review Status**: IN_REVIEW

### T-009: OpenCode Orchestration Setup
- **Objective**: Complete OpenCode multi-agent orchestration system
- **Priority**: P1
- **Assigned Agent**: principal-architect
- **Supporting Skills**: ecc/agent-architecture-audit, ecc/team-agent-orchestration
- **Dependencies**: None
- **Files Owned**: .opencode/agents/, .opencode/skills/, .opencode/commands/, opencode.jsonc, .orchestration/*
- **Acceptance Criteria**:
  - All 6 skill repositories registered
  - Master Orchestrator primary agent
  - 10 specialist subagents
  - Skill registry complete
  - Custom commands created
- **State**: IN_PROGRESS
- **Review Status**: IN_REVIEW