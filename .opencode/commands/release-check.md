# /release-check Command

Execute integrated release readiness verification across all quality gates.

## Usage
```
/release-check [--full]
```

## Behavior

1. **Pre-flight Checks**:
   - Git status clean
   - All tests passing
   - Build successful
   - No security regressions

2. **Quality Gates**:
   - Backend tests (122/122)
   - Frontend build + TypeScript
   - Docker build + WeasyPrint
   - PDF generation smoke test
   - Security audit summary

3. **Integration Verification**:
   - Full scan pipeline (sandbox target)
   - PDF generation + download
   - ReportsView data + actions
   - Authorization flow

4. **Documentation**:
   - CURRENT_STATE.md updated
   - CHANGELOG updated
   - Version bumped

5. **Docker Image**:
   - Build production image
   - Verify health checks
   - Push to registry (if configured)

## Gates (All Must Pass)

| Gate | Command | Threshold |
|------|---------|-----------|
| Backend Tests | `pytest tests/ -q` | 100% pass |
| Frontend Build | `npm run build` | Success |
| TypeScript | `npx tsc --noEmit` | No errors |
| Docker Build | `docker compose build` | Success |
| WeasyPrint | `docker run ... python -c "from weasyprint import HTML"` | Success |
| PDF Smoke Test | Generate + download test PDF | Valid PDF |
| Security | `/security-audit all` | No CRITICAL |

## Options
- `--full` - Run all gates including integration tests
- `--skip <gate>` - Skip specific gate (use cautiously)
- `--dry-run` - Show what would run without executing

## Example
```
/release-check
/release-check --full
/release-check --skip docker
```

## Output
Release readiness report with:
- Gate results (PASS/FAIL)
- Evidence for each gate
- Blockers and warnings
- Go/No-Go recommendation