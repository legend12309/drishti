# DRISHTI Decision Log

| Date | Decision | Author | Rationale | Related ADR |
|------|----------|--------|-----------|-------------|
| 2026-10-30 | Use Debian unstable for libpangoft2-1.0-0 | devops-engineer | WeasyPrint 70+ requires libpangoft2 only in unstable | ADR-003 |
| 2026-10-30 | Fix SPA catch-all with regex /{full_path:^(?!api/).*$} | backend-engineer | Prevents API routes serving index.html | ADR-006 |
| 2026-10-30 | Add GET /orchestrator/workflows for ReportsView | backend-engineer | Frontend needs list endpoint for reports table | ADR-005 |
| 2026-10-30 | Apply missing migration 010_scan_reports.sql | database-reviewer | scan_reports table was missing in PostgreSQL | - |
| 2026-10-30 | Fix WeasyPrint 70+ API (font_config parameter) | backend-engineer | API changed in WeasyPrint 70+ | ADR-004 |
| 2026-10-30 | Fix Nmap XML parser to allow standard DOCTYPE | backend-engineer | Valid Nmap XML with DOCTYPE was rejected | ADR-009 |
| 2026-10-30 | Enforce Nmap timeout inside monitor loop | backend-engineer | 1107s hang without timeout enforcement | ADR-009 |
| 2026-10-30 | Trivy target typing - website = SKIPPED | backend-engineer | Hostname treated as filesystem path | ADR-010 |
| 2026-10-30 | ZAP real passive scan with polling | backend-engineer | 0.74s fake completion | ADR-011 |
| 2026-10-30 | Persist synthetic auth to DB | backend-engineer | Worker revalidation failing | ADR-012 |
| 2026-10-30 | Create ReportsView with full CRUD | frontend-engineer | Reports section missing | ADR-005 |
| 2026-10-30 | Add 'reports' to TabId type and Sidebar | frontend-engineer | Navigation integration | ADR-005 |
| 2026-10-30 | Use regex in SPA catch-all for /api/* exclusion | backend-engineer | API routes returning HTML | ADR-006 |