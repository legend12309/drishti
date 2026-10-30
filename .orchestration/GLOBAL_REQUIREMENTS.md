# DRISHTI Global Requirements

## Functional Requirements

### Core Platform
- [ ] Sequential scanner pipeline execution
- [ ] DNS TXT authorization enforcement
- [ ] Multi-scanner orchestration with dependencies
- [ ] Real-time progress streaming (SSE)
- [ ] Findings persistence and correlation
- [ ] AI-assisted analysis integration
- [ ] Professional PDF report generation
- [ ] Secure report download with authorization

### Security (NON-NEGOTIABLE)
- [ ] Authorization required before ANY scan execution
- [ ] DNS TXT challenge verification with expiration
- [ ] IP scope validation on every network call
- [ ] SSRF prevention at all layers
- [ ] XML external entity rejection
- [ ] Subprocess timeout enforcement
- [ ] RLS policies for tenant isolation
- [ ] Audit logging for all security events

### Scanner Requirements
- **Nmap**: Real XML parsing, XXE rejected, timeout enforced
- **HTTPX**: JSONL parsing, redirect stripping, scope validation
- **ZAP**: Real passive scan with polling, not fake completion
- **Nuclei**: 300s budget, partial results preserved
- **Trivy**: Target typing, website = SKIPPED with reason
- **SQL Assessment**: Safe, configurable, non-destructive

### PDF Report Generation
- [ ] WeasyPrint runtime in Docker (libpangoft2-1.0-0 from unstable)
- [ ] Jinja2 templates with professional styling
- [ ] Unicode and multi-page support
- [ ] Secure download via authenticated API
- [ ] Content-Disposition with safe filename

### Frontend Requirements
- [ ] ReportsView at `/reports` with full CRUD
- [ ] Navigation integration in Sidebar
- [ ] Real API data (no placeholders)
- [ ] Loading/empty/error/retry states
- [ ] Download handles binary PDF responses
- [ ] Responsive, accessible, DRISHTI-themed

## Technical Requirements

### Backend
- FastAPI with proper async patterns
- PostgreSQL with asyncpg
- Proper error handling and logging
- API versioning and contracts
- Health checks and monitoring

### Frontend
- React 18 + Vite + TypeScript
- Tailwind CSS with DRISHTI design tokens
- Material Symbols for icons
- Vite proxy for API in dev

### Docker
- Multi-stage build for size optimization
- Health checks for all services
- Non-root user execution
- Proper volume mounting

### Testing
- 122+ backend tests passing
- Frontend build + TypeScript clean
- Integration tests for scanner pipeline
- Security tests for authorization

## Quality Gates
- All 122 backend tests pass
- Frontend build succeeds
- TypeScript strict mode clean
- PDF smoke test in container
- Security scan pipeline test