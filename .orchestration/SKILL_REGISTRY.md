# DRISHTI Skill Registry & Capability Matrix

**Status:** Audited & Remediated (November 02, 2026)  
**Global Skills Engine:** `~/.gemini/config/skills/` (475 Native Production Skills)  
**Project Integration:** `D:\drishti\.opencode\skills\`  

---

## 1. Registered Skill Frameworks

| Framework | Primary Purpose | Source Engine Location | Runtime Status | Active Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **ecc** | 200+ Enterprise Engineering Skills | `~/.gemini/config/skills/` | ✅ Active (Global Native) | Backend, FastAPI, Docker, K8s, CI/CD, Architecture |
| **ponytail** | Engineering Discipline & Code Simplification | `~/.gemini/config/skills/ponytail*` | ✅ Active (Global Native) | Anti-bloat, debt reduction, complexity refactoring |
| **impeccable** | UI/UX & Frontend Visual Polish | `~/.gemini/config/skills/impeccable` | ✅ Active (Global Native) | High-contrast HUD design, typography, accessibility |
| **agent-skills** | Complete Software Engineering Lifecycle | `~/.gemini/config/skills/` | ✅ Active (Global Native) | Spec-driven dev, TDD, incremental release, ADRs |
| **designer-skills** | Product Design & User Research | `~/.gemini/config/skills/` | ✅ Active (Global Native) | Interaction design, design systems, visual critique |
| **reverse-skill** | Cybersecurity & ASM Intelligence | Native DRISHTI Services + AI Mesh | 🔄 Pure-Python Emulated | NVD 2.0, Metasploit tags, Dijkstra graph, WAF hotfixes |

---

## 2. Skill Routing Matrix by Engineering Domain

| Task Category | Primary Skills | Secondary Supporting Skills |
| :--- | :--- | :--- |
| **Vulnerability Analysis** | `security-and-hardening`, `security-review` | `cve-correlation`, `remediation_engine` |
| **Penetration Testing Intel** | `metasploit-intelligence`, `risk_engine` | `nvd_models`, `vulnerability_service` |
| **Code Quality & Refactoring** | `ponytail`, `code-simplification` | `code-review-and-quality`, `clean-architecture` |
| **Frontend Engineering** | `frontend-patterns`, `react-patterns`, `impeccable` | `vite-patterns`, `frontend-a11y` |
| **Backend Engineering** | `fastapi-patterns`, `backend-patterns`, `python-patterns` | `contract-first`, `api-and-interface-design` |
| **Database Operations** | `postgres-patterns`, `database-migrations` | `sqlite-wal`, `deprecation-and-migration` |
| **DevOps & Infrastructure** | `docker-patterns`, `deployment-patterns` | `ci-cd-and-automation`, `observability` |
| **AI / Multi-Model Router** | `llm-router`, `intelligence_explainer` | `cost-aware-llm-pipeline`, `guard-middleware` |
| **Automated Testing & QA** | `test-driven-development`, `python-testing` | `e2e-testing`, `verification-loop` |
| **System Architecture** | `architecture-decision-records`, `spec-driven-development`| `planning-and-task-breakdown` |

---

## 3. Skill Health & Verification Audit

| Skill Group | Physical Source | Runtime Availability | Last Verified | Health Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **ecc** | `~/.gemini/config/skills/` | ✅ Available | 2026-11-02 | Fully functional across all 200+ modules |
| **ponytail** | `~/.gemini/config/skills/ponytail` | ✅ Available | 2026-11-02 | Fully functional (6 core simplification skills) |
| **impeccable** | `~/.gemini/config/skills/impeccable` | ✅ Available | 2026-11-02 | Fully functional for tactical UI/UX design |
| **agent-skills** | `~/.gemini/config/skills/` | ✅ Available | 2026-11-02 | Fully functional (24 lifecycle skills) |
| **designer-skills**| `~/.gemini/config/skills/` | ✅ Available | 2026-11-02 | Fully functional (9 design strategy skills) |
| **reverse-skill** | Native Python Services | ✅ Native Service | 2026-11-02 | Emulated natively in DRISHTI pure-python core |

---

## 4. Operational Rules for Development

1. **Native Discovery:** Agents automatically discover and load skills directly from `~/.gemini/config/skills/`.
2. **Zero Phantom Paths:** Never invoke legacy or non-existent tools paths (deprecated).
3. **Just-In-Time Loading:** Load only domain-specific skills required for the active phase to conserve context budget.
4. **Evidence Grounding:** All security findings and defense rules must be backed by deterministic code templates or verified telemetry.
