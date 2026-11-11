# DRISHTI // Attack Surface Management & Threat Intelligence

DRISHTI is an open-source, pure-Python attack surface management and defensive intelligence platform. It discovers perimeter assets via Certificate Transparency logs, maps exposure chains using topological graph pathfinding, correlates discovered services against Metasploit modules, and generates defensive WAF rules and patch diffs.

---

## Core Capabilities (7 Operational Engines)

1. **01_ COCKPIT (`DashboardView`):** Tri-pane security operations console showing perimeter metrics, active attack paths, and 1-click defense configurations.
2. **02_ RECON (`ReconView`):** Dual-layer reconnaissance combining passive Certificate Transparency log querying (`crt.sh`) and asynchronous TCP port scanning across standard web and administrative ports.
3. **03_ INTEL (`IntelligenceView`):** Vulnerability correlation matching banner signatures to CVE/CWE entries and Rapid7 Metasploit auxiliary/exploit modules, paired with an offline-resilient AI guidance copilot.
4. **04_ GRAPH (`GraphView`):** NetworkX-powered directed multigraph modeling infrastructure nodes (domains, IPs, open ports, software products, CVEs) and computing the shortest traversal paths to critical assets using Dijkstra's algorithm.
5. **05_ GUARD (`GuardrailsView`):** Active authorization management using ACME-style DNS TXT challenge tokens (`drishti-verify=...`) and automated anti-SSRF filtering for private networks (RFC 1918) and cloud metadata services (`169.254.169.254`).
6. **06_ REPORTS (`ReportsView`):** Structured compliance and executive export engine supporting HTML, JSON, browser-native PDF generation, and OASIS STIX 2.1 threat intelligence bundles.
7. **07_ CONFIG (`SettingsView`):** Dynamic runtime management for LLM API keys (Groq, NVIDIA NIM, Google Gemini, Hugging Face) and local fallback modes.

---

## What DRISHTI Does NOT Do

To maintain legal compliance and prevent operational disruption, DRISHTI adheres to strict design boundaries:
- **No Payload Weaponization / Active Exploitation:** DRISHTI does not fire exploits, execute remote shells, or deliver destructive payloads against target infrastructure. It correlates weaponization feasibility metadata and generates `.rc` Metasploit resource templates for controlled validation.
- **No Hardware Security Enclave:** Host machine attestation is derived via HMAC-SHA256 signatures of CPU, hostname, and codebase Merkle trees. It does not employ physical TPM chips, Intel SGX, or AMD SEV hardware enclaves.
- **No Direct AI Multi-Model Consensus:** The AI advisory core operates as a sequential circuit-breaker fallback router (Groq -> NVIDIA -> Gemini -> Hugging Face -> Offline Rule-Based Synthetic Engine). It returns the first valid response rather than aggregating multi-model votes.
- **No Internal Hidden DNS Brute-Forcing:** Passive reconnaissance relies strictly on public certificate transparency logs and standard DNS resolution. It cannot uncover internal records not exposed in public zones.

---

## Prerequisites

- **Operating System:** Windows 10/11, Ubuntu 22.04+, or macOS Sonoma+
- **Python:** Python 3.11 or Python 3.12 (64-bit)
- **Node.js:** Node.js 18 LTS or Node.js 20 LTS (with npm)
- **Git:** Installed and available on system PATH

---

## Quickstart

### 1. Automated Installation (Windows)
Double-click `install.bat` or run:
```powershell
.\install.bat
```
This provisions a Python virtual environment (`.venv`), installs Python dependencies, and builds the React frontend.

### 2. Launching the Platform
Run:
```powershell
.\start_drishti.bat
```
The FastAPI backend starts on `http://127.0.0.1:8000`, serving both the REST API and the bundled frontend interface.

### 3. Manual Startup
```bash
# Backend setup
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Frontend build
cd frontend
npm install
npm run build
cd ..

# Run server
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

---

## Verification & Testing

DRISHTI includes automated unit, integration, and security verification suites:

```bash
# Run 134-test unit and integration suite
pytest tests/ -q

# Run 43-vector Red Team security audit
python tests/red_team_full_audit.py
```

Audit categories verified:
- Path Traversal (CWE-22) prevention on static file handlers
- Sensitive File Protection (CWE-538) blocking access to `.env` and `.git`
- SSRF Filtering (CWE-918) restricting loopback, RFC 1918, and AWS/GCP metadata endpoints
- Scope Authorization verification via DNS TXT tokens
- Topological Dijkstra attack path computation
- STIX 2.1 JSON schema validation
- SQLite Write-Ahead Logging (WAL) integrity

---

## Repository Structure

```
drishti/
├── backend/
│   ├── main.py                    # FastAPI application & security middleware
│   ├── routers/                   # API routes (recon, intel, graph, defense, reports)
│   └── services/                  # Scanning, attack graph, LLM router, STIX engine
├── frontend/
│   ├── src/                       # React 18 + TypeScript tactical interface
│   │   ├── components/            # HUD elements, TopUtilityBar, Sidebar, Modals
│   │   └── views/                 # 7 operational engine views
│   └── vite.config.ts             # Vite configuration
├── tests/                         # Pytest test files and red team audit script
├── data/                          # SQLite database and report storage
├── install.bat                    # Windows automated dependency installer
├── start_drishti.bat              # Windows platform launcher
├── requirements.txt               # Pinned Python package dependencies
└── LICENSE                        # MIT License
```

---

## License

This project is licensed under the [MIT License](LICENSE).
