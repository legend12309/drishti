# DRISHTI Just-In-Time (JIT) Production Skill Bundles

To eliminate context window bloat and maximize developer & agent execution throughput, DRISHTI groups its 475 global skills into **5 High-Performance Production Bundles**.

---

## 1. Backend & API Services (`bundle-backend`)

**Primary Role:** Backend Engineer / API Developer  
**Activated When:** Modifying FastAPI routers, endpoints, Pydantic models, or async scanning pipelines.

| Skill | Source | Capability |
| :--- | :--- | :--- |
| `fastapi-patterns` | `~/.gemini/config/skills/fastapi-patterns` | Modern FastAPI route design, DI, lifespan events, middleware |
| `backend-patterns` | `~/.gemini/config/skills/backend-patterns` | Async architecture, error handling, worker threads |
| `python-testing` | `~/.gemini/config/skills/python-testing` | Pytest fixtures, async test loops, mocks, coverage |
| `postgres-patterns` | `~/.gemini/config/skills/postgres-patterns` | Query optimization, connection pools, SQLite WAL fallback |
| `contract-first` | `~/.gemini/config/skills/contract-first` | Strict Pydantic model contracts without schema drift |

---

## 2. Tactical Frontend & Cockpit HUD (`bundle-frontend`)

**Primary Role:** Frontend Engineer / UI Polish Specialist  
**Activated When:** Modifying React views, Vite build, Tailwind CSS, or Tri-Pane Cockpit layouts.

| Skill | Source | Capability |
| :--- | :--- | :--- |
| `frontend-patterns` | `~/.gemini/config/skills/frontend-patterns` | React 18, Vite 5.4, component state architecture |
| `react-patterns` | `~/.gemini/config/skills/react-patterns` | Custom hooks, clean render lifecycles, zero layout shifts |
| `impeccable` | `~/.gemini/config/skills/impeccable` | High-contrast Obsidian HUD design, typography, accessibility |
| `emil-design-eng` | `~/.gemini/config/skills/emil-design-eng` | Micro-interactions, tactile click feedback, crisp transitions |
| `frontend-a11y` | `~/.gemini/config/skills/frontend-a11y` | WCAG 2.1 AA compliance, keyboard navigation |

---

## 3. Cyber Threat Intelligence & Autonomous Defense (`bundle-security`)

**Primary Role:** Security Auditor / SecOps Engineer  
**Activated When:** Working on vulnerability correlation, Metasploit tags, WAF rules, or scope enforcement.

| Skill | Source | Capability |
| :--- | :--- | :--- |
| `security-and-hardening` | `~/.gemini/config/skills/security-and-hardening` | OWASP Top 10 defense, SSRF prevention, input sanitization |
| `security-review` | `~/.gemini/config/skills/security-review` | Code audit, credential leak detection, authorization gates |
| `remediation-engine` | `backend/services/remediation_engine.py` | 1-Click Cloudflare WAF, Nginx ModSec, iptables, patch diffs |
| `cve-correlation` | `backend/services/vulnerability_service.py` | NVD 2.0 API, EPSS probability, CISA KEV weaponization |
| `verification-probe` | `backend/api/defense.py` | Diagnostic micro-probes testing HTTP 403 boundary enforcement |

---

## 4. Attack Graph & Dijkstra Pathfinding (`bundle-graph`)

**Primary Role:** Risk Engineer / Graph Architect  
**Activated When:** Optimizing NetworkX attack graphs, node weight algorithms, or lateral movement heuristics.

| Skill | Source | Capability |
| :--- | :--- | :--- |
| `risk-engine` | `backend/services/risk_engine.py` | Dijkstra shortest path algorithm with 0.40x MSF friction multiplier |
| `graph-builder` | `backend/services/graph_builder.py` | Directed multigraph generation from DMZ ingress to Crown Jewels |
| `performance-optimization`| `~/.gemini/config/skills/performance-optimization`| Graph traversal profiling, sub-10ms path calculation |
| `networkx-patterns` | `backend/services/` | Node clustering, edge attributes, topological sort |

---

## 5. Continuous Testing & Quality Assurance (`bundle-qa`)

**Primary Role:** QA Engineer / Test Automation Specialist  
**Activated When:** Writing unit tests, integration tests, E2E flows, or pre-commit verification.

| Skill | Source | Capability |
| :--- | :--- | :--- |
| `test-driven-development`| `~/.gemini/config/skills/test-driven-development`| Red-Green-Refactor methodology, test-first design |
| `python-testing` | `~/.gemini/config/skills/python-testing` | Unit test fixtures, AsyncMock, TestClient integration |
| `e2e-testing` | `~/.gemini/config/skills/e2e-testing` | End-to-end user journeys and state verification |
| `verification-loop` | `~/.gemini/config/skills/verification-loop` | Pre-merge verification checklist and diff review |
| `audit-skills` | `scripts/audit_skills.py` | Automated skill ecosystem and path integrity verification |
