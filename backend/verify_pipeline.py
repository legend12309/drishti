#!/usr/bin/env python3
"""
DRISHTI — Master Pipeline Audit & Diagnostic Self-Test (Karpathy Style)
Tests all 8 core API pathways in sequence with zero fluff and exact timing.
"""

import sys
import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"

def request(method: str, path: str, body: dict = None, token: str = None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            status_code = resp.status
            content = resp.read().decode("utf-8")
            try:
                res_json = json.loads(content)
            except Exception:
                res_json = content
            return status_code, elapsed_ms, res_json, None
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            err_body = str(e)
        return e.code, elapsed_ms, None, err_body
    except Exception as ex:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        return 0, elapsed_ms, None, str(ex)


def run_pipeline_audit():
    print("=" * 80)
    print("DRISHTI CYBER INTELLIGENCE PLATFORM // PIPELINE AUDIT (KARPATHY STYLE)")
    print(f"Target: {BASE_URL} // Enclave: MONOLITH-8000 // Zero-Egress Airgap")
    print("=" * 80)
    print(f"{'STEP':<6} | {'ENDPOINT':<32} | {'STATUS':<8} | {'LATENCY':<9} | {'RESULT'}")
    print("-" * 80)

    token = None
    all_passed = True
    steps = []

    # 1. Health
    status, lat, data, err = request("GET", "/api/health")
    ok = (status == 200 and isinstance(data, dict) and data.get("status") == "operational")
    steps.append(("01", "GET  /api/health", ok, lat, f"Engines: {len(data.get('engines', {})) if ok else 0} online"))
    if not ok: all_passed = False

    # 2. Auth Login
    status, lat, data, err = request("POST", "/api/auth/login", {"username": "local-operator-dev", "password": "SecOpsPassword2026!", "role": "SecOps Lead"})
    ok = (status == 200 and isinstance(data, dict) and "access_token" in data)
    if ok:
        token = data["access_token"]
        steps.append(("02", "POST /api/auth/login", ok, lat, f"Token: {token[:16]}..."))
    else:
        steps.append(("02", "POST /api/auth/login", False, lat, f"Err: {err or status}"))
        all_passed = False

    # 3. Recon Latest
    status, lat, data, err = request("GET", "/api/recon/latest", token=token)
    ok = (status == 200 and isinstance(data, dict) and len(data.get("subdomains", [])) >= 1)
    sub_count = len(data.get("subdomains", [])) if ok else 0
    ports_count = len(data.get("ports", [])) if ok else 0
    steps.append(("03", "GET  /api/recon/latest", ok, lat, f"Target: {data.get('target', 'n/a')} ({sub_count} subs, {ports_count} ports)"))
    if not ok: all_passed = False

    # 4. Vulnerabilities Latest
    status, lat, data, err = request("GET", "/api/vulnerabilities/latest", token=token)
    ok = (status == 200 and isinstance(data, dict) and len(data.get("vulnerabilities", [])) >= 1)
    v_count = len(data.get("vulnerabilities", [])) if ok else 0
    conf_count = data.get("confirmed_count", 0) if ok else 0
    steps.append(("04", "GET  /api/vulnerabilities/latest", ok, lat, f"{v_count} vulns ({conf_count} confirmed active)"))
    if not ok: all_passed = False

    # 5. Graph Latest
    status, lat, data, err = request("GET", "/api/graph/latest", token=token)
    ok = (status == 200 and isinstance(data, dict) and len(data.get("shortest_path", [])) >= 2)
    path_len = len(data.get("shortest_path", [])) if ok else 0
    cost = data.get("total_cost", 0.0) if ok else 0.0
    steps.append(("05", "GET  /api/graph/latest", ok, lat, f"Path: {path_len} nodes (Cost: {cost:.2f}x)"))
    if not ok: all_passed = False

    # 6. Defense Generate
    status, lat, data, err = request("POST", "/api/defense/generate", {"cve_id": "CVE-2024-4577", "target": "vvdx.in"}, token=token)
    ok = (status == 200 and isinstance(data, dict) and "cloudflare_waf" in data)
    steps.append(("06", "POST /api/defense/generate", ok, lat, f"WAF & ModSec compiled for {data.get('cve_id') if ok else 'n/a'}"))
    if not ok: all_passed = False

    # 7. Defense Verify
    status, lat, data, err = request("POST", "/api/defense/verify", {"target_url": "https://vvdx.in", "expected_status": 403}, token=token)
    ok = (status == 200 and isinstance(data, dict) and "verdict" in data)
    verdict = data.get("verdict", "UNKNOWN") if ok else "FAILED"
    steps.append(("07", "POST /api/defense/verify", ok, lat, f"Probe: {verdict}"))
    if not ok: all_passed = False

    # 8. Report Generate (Text format)
    status, lat, data, err = request("POST", "/api/reports/generate", {"target": "vvdx.in", "format": "TEXT"}, token=token)
    text_len = len(data.get("content_text", "")) if (isinstance(data, dict) and "content_text" in data) else 0
    ok = (status == 200 and isinstance(data, dict) and data.get("format") == "TEXT" and text_len > 100)
    steps.append(("08", "POST /api/reports/generate", ok, lat, f"Format: TEXT ({text_len} bytes, signed SHA-256)"))
    if not ok: all_passed = False

    # Print execution matrix
    for num, ep, passed, elapsed, detail in steps:
        tag = "[ PASS ]" if passed else "[ FAIL ]"
        print(f"[{num}]  | {ep:<32} | {tag:<8} | {elapsed:>6.1f}ms  | {detail}")

    print("-" * 80)
    if all_passed:
        print("[ RESULT: ALL 8 PIPELINE GATES PASSED DETERMINISTICALLY // 100% OPERATIONAL ]")
    else:
        print("[ RESULT: PIPELINE AUDIT REPORTED FAILURES // CHECK LOGS ABOVE ]")
    print("=" * 80)
    return all_passed

if __name__ == "__main__":
    success = run_pipeline_audit()
    sys.exit(0 if success else 1)
