# DRISHTI Architecture Decision Records (ADRs)

## ADR-001: Sequential Scanner Pipeline
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Multi-scanner orchestration requires dependency resolution
**Decision**: Sequential execution with explicit stage dependencies (Nmap → HTTPX → ZAP → Nuclei → SQL → Trivy)
**Consequences**: 
- Simpler dependency management
- Longer total execution time
- Easier debugging and cancellation

## ADR-002: DNS TXT Authorization
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Need to verify domain ownership before scanning
**Decision**: DNS TXT challenge with 24h challenge lifetime, 30-day verified validity
**Consequences**:
- Prevents unauthorized scans
- Requires DNS propagation time
- Challenges expire if not verified

## ADR-003: Docker Base Image - python:3.12-slim
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Need minimal base for scanner binaries + Python runtime
**Decision**: python:3.12-slim (Debian Trixie) with unstable repo for libpangoft2-1.0-0
**Consequences**:
- Small base image (~150MB)
- Unstable repo for libpangoft2-1.0-0 (WeasyPrint 70+ requirement)
- All scanner binaries installed in build stage

## ADR-004: WeasyPrint for PDF Generation
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Need professional PDF reports from HTML templates
**Decision**: WeasyPrint 70+ with Jinja2 templates
**Consequences**:
- Requires GTK libraries (libpangoft2-1.0-0 from Debian unstable)
- Professional output with CSS support
- Unicode and multi-page support

## ADR-005: Sequential Orchestration with SSE
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Need real-time progress visibility
**Decision**: Server-Sent Events for progress streaming with reconnect support
**Consequences**:
- Real-time UI updates
- Reconnection handling required
- Event replay on reconnect

## ADR-006: SPA with API Proxy
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Single-page React app with backend API
**Decision**: Vite dev proxy (/api → localhost:8000), SPA catch-all with /api/* exclusion
**Consequences**:
- Clean development experience
- API routes must not conflict with SPA routes
- Production serves static files from /frontend/dist

## ADR-007: Database - PostgreSQL with RLS
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Multi-tenant security data storage
**Decision**: PostgreSQL with Row Level Security for tenant isolation
**Consequences**:
- Tenant isolation at database level
- Supabase compatibility
- Migration-based schema management

## ADR-008: AI Provider Fallback Chain
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Multiple LLM providers for reliability
**Decision**: Priority order: Gemini → Groq → NVIDIA → Hugging Face → Offline Synthetic
**Consequences**:
- Automatic fallback on failures
- Cost optimization via routing
- Offline synthetic as last resort

## ADR-009: Scanner Timeout Enforcement
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Nmap 1107s hang incident
**Decision**: Enforce timeout inside monitoring loop, not just asyncio.wait_for
**Consequences**:
- Hard deadline enforcement
- Process cleanup on timeout
- Nuclei 300s, others 120s default

## ADR-010: Trivy Target Typing
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Trivy treating hostnames as filesystem paths
**Decision**: Explicit target typing (filesystem/image/repository/website), website = SKIPPED
**Consequences**:
- No false filesystem errors for websites
- Clear reason logged for skipped stages
- Explicit target classification required

## ADR-011: ZAP Real Passive Scan
**Date**: 2026-10-30
**Status**: Accepted
**Context**: ZAP completing in 0.74s with 0 findings
**Decision**: Implement real spider → passive scan → poll until complete
**Consequences**:
- Real findings from ZAP
- Longer stage duration
- Proper completion polling

## ADR-012: Sandbox Authorization Persistence
**Date**: 2026-10-30
**Status**: Accepted
**Context**: Worker revalidation failing for synthetic authorizations
**Decision**: Persist synthetic authorizations to database before worker starts
**Consequences**:
- Classic scan path now works
- Worker revalidation finds real DB row
- No trust in client-supplied IDs