# DRISHTI Project Context

## Project Overview
**DRISHTI** - Cyber Command & Threat Intelligence Platform
- **Architecture**: React + Vite + TypeScript (frontend), FastAPI + Python (backend)
- **Database**: PostgreSQL / Supabase with RLS policies
- **Deployment**: Docker Compose on Windows host
- **Scanners**: Nmap, ZAP, Nuclei, Trivy, HTTPX (sequential pipeline)
- **AI Providers**: Gemini, Groq, NVIDIA, Hugging Face (with fallback chains)
- **PDF Generation**: WeasyPrint + Jinja2 (fixed in Docker with libpangoft2-1.0-0 from Debian unstable)

## Current State (as of 2026-10-30)

### ✅ Verified Working
- Docker build with WeasyPrint dependencies (libpangoft2-1.0-0 from Debian unstable)
- PDF generation in container: "WeasyPrint works!"
- Frontend build: 281.80 kB, TypeScript clean
- Backend tests: 122/122 passing
- ReportsView at `/reports` with download/generate actions
- API endpoints for report generation and download

### 🔄 Active / Pending
- curezy.in DNS authorization: **EXPIRED** - all authorizations expired, new challenge required
- Git repository: Not initialized

### 📁 Key Files Modified
- `Dockerfile` - Added WeasyPrint GTK dependencies + libpangoft2-1.0-0
- `backend/main.py` - Fixed SPA catch-all route to exclude `/api/*`
- `backend/api/scans.py` - Added `GET /orchestrator/workflows` endpoint
- `backend/services/report_generator.py` - Fixed WeasyPrint 70+ API
- `frontend/src/views/ReportsView.tsx` - New complete ReportsView component
- `frontend/src/components/Sidebar.tsx` - Added "PDF Reports" navigation
- `frontend/src/types.ts` - Added `'reports'` to `TabId` type
- `data/migrations/010_scan_reports.sql` - Applied (was missing)

## Security Constraints (MANDATORY)
1. Explicit target authorization required before any scan
2. Valid and unexpired DNS TXT verification
3. Server-side ownership validation
4. IP scope validation and SSRF prevention
5. DNS rebinding and redirect protection
6. Safe subprocess execution with bounded timeout/output
7. XML external entity protection
8. Supabase RLS and tenant isolation
9. Secret protection in all configurations
10. Evidence-backed findings only
11. Authorized report downloads only

## Intended Scan Pipeline
```
Domain Input
    ↓
DNS TXT Authorization
    ↓
DNS Resolution and Scope Validation
    ↓
Nmap → HTTPX → OWASP ZAP → Nuclei → SQL Assessment → Trivy (if applicable)
    ↓
Findings Correlation
    ↓
AI Analysis
    ↓
PDF Report
```

## Technology Stack
- **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Material Symbols
- **Backend**: FastAPI, Python 3.12, asyncpg, SQLAlchemy-style adapters
- **Database**: PostgreSQL 16 (local Docker), Supabase (remote)
- **Scanners**: Nmap 7.95, HTTPX v1.6.0, Nuclei v3.3.2, Trivy 0.76.1, ZAP 2.17.0
- **AI**: Gemini, Groq, NVIDIA Nemotron, Hugging Face (with routing/fallback)
- **PDF**: WeasyPrint 70+, Jinja2 templates
- **Container**: python:3.12-slim (Debian Trixie) + Debian unstable for libpangoft2