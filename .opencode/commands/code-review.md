# /code-review Command

Coordinate independent code review with appropriate specialist reviewers.

## Usage
```
/code-review <files-or-pr> [--reviewer <agent>]
```

## Behavior

1. **Identify Files** - Parse changed files from input
2. **Classify Changes** - Map to domains (backend, frontend, database, security, etc.)
3. **Select Reviewers** - Assign appropriate specialist agents:
   - Backend changes → backend-engineer + security-auditor
   - Frontend changes → frontend-engineer + product-designer
   - Database changes → database-reviewer + backend-engineer
   - Security changes → security-auditor + principal-architect
4. **Review Process**:
   - Each reviewer inspects code independently
   - Check against domain-specific quality gates
   - Verify tests exist and pass
   - Check security constraints
   - Validate API contracts
5. **Consolidation** - Orchestrator collects reviews, resolves conflicts
6. **Decision** - Approve, Request Changes, or Block

## Reviewer Assignment Rules

| File Pattern | Primary Reviewer | Secondary Reviewer |
|--------------|------------------|-------------------|
| backend/**/*.py | backend-engineer | security-auditor |
| frontend/src/**/*.tsx | frontend-engineer | product-designer |
| frontend/src/**/*.ts | frontend-engineer | - |
| data/migrations/*.sql | database-reviewer | backend-engineer |
| Dockerfile | devops-engineer | backend-engineer |
| docker-compose.yml | devops-engineer | - |
| *.md (docs) | documentation-writer | principal-architect |

## Options
- `--reviewer <agent>` - Override default reviewer
- `--security` - Force security-auditor review
- `--strict` - Require all reviewers to approve

## Example
```
/code-review backend/services/report_generator.py
/code-review frontend/src/views/ReportsView.tsx --reviewer product-designer
/code-review data/migrations/010_scan_reports.sql --strict
```

## Output
Consolidated review with:
- Individual reviewer findings
- Consolidated decision (APPROVE / CHANGES_REQUESTED / BLOCKED)
- Required changes with file/line references
- Test validation results