# DRISHTI // Sovereign Cyber Defense Platform
### Offline Standalone Client Deployment & Presentation Guide

---

## 1. Quick Start (Windows — Recommended for Presentations)

### Option A: Double-Click Desktop Application (Recommended)
1. Double-click **`start_desktop_app.bat`**.
2. DRISHTI will start its internal engine and open in its own **dedicated standalone desktop window** (borderless application mode, without browser tabs or address bar).

### Option B: Standard Browser Launcher
1. Double-click **`start_drishti.bat`**.
2. DRISHTI will start its core engine and automatically launch your default web browser to:
   ```
   http://127.0.0.1:8000
   ```
3. The cinematic biometric ocular login interface will appear.

---

## 2. Default Operator Clearance Credentials
* **Username**: `Alex Morgan` (or `local-operator-dev`)
* **Password**: `any-password` (Air-gap enclave auto-authenticates authorized operator session)
* **Clearance**: `LEVEL 5 // TOP SECRET // SI-TK / GBD-AUTH`
* **Role**: `SecOps Lead`

---

## 3. Fresh Machine Installation (If Python environment is not set up)
If running on a brand-new computer that does not have the virtual environment:
1. Double-click **`install.bat`**.
2. It will automatically create `.venv`, install all Python dependencies from `requirements.txt`, and configure the local SQLite database.
3. Once complete, it prompts you to launch DRISHTI immediately.

---

## 4. Architecture & Database Engine (Offline Hermetic Air-Gap Mode)
* **Active Database**: Local SQLite in **WAL (Write-Ahead Logging)** mode (`data/drishti.db`).
* **Zero Cloud Dependencies**: Runs 100% locally with zero internet egress required.
* **Latency**: Ultra-fast **1.8ms** internal query response time.
* **Attestation Seal**: Every response and tactical dossier is cryptographically attested with a hardware-bound enclave node ID (`DRISHTI-NODE-...`) and Merkle tree hash validation.

---

## 5. How to Stop the Platform
* Double-click **`stop_drishti.bat`**, or close the terminal window.
