import urllib.request
import urllib.parse
import json
import time
import sqlite3
import sys
sys.path.insert(0, r"D:\drishti")

def run_audit():
    results = []
    
    # 1. Health check
    t0 = time.time()
    try:
        with urllib.request.urlopen("http://127.0.0.1:8000/api/health") as res:
            data = json.loads(res.read().decode())
            dur = (time.time() - t0) * 1000
            engines = data.get("engines", {})
            all_ready = all(v.get("status") == "ready" for v in engines.values())
            results.append({
                "subsystem": "Core API & 5 Engine Armament",
                "status": "PASS" if (res.status == 200 and all_ready) else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"Engines: {list(engines.keys())} all operational"
            })
    except Exception as e:
        results.append({"subsystem": "Core API & 5 Engine Armament", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 2. Database Pristine Zero-Data Check
    t0 = time.time()
    try:
        conn = sqlite3.connect(r"D:\drishti\data\drishti.db")
        cur = conn.cursor()
        scans_count = cur.execute("SELECT count(*) FROM scans").fetchone()[0]
        findings_count = cur.execute("SELECT count(*) FROM scan_findings").fetchone()[0]
        paths_count = cur.execute("SELECT count(*) FROM attack_paths").fetchone()[0]
        conn.close()
        dur = (time.time() - t0) * 1000
        is_clean = (scans_count == 0 and findings_count == 0 and paths_count == 0)
        results.append({
            "subsystem": "Database Pristine Zero-Data State",
            "status": "PASS" if is_clean else "FAIL",
            "latency_ms": round(dur, 2),
            "detail": f"scans={scans_count}, findings={findings_count}, attack_paths={paths_count}"
        })
    except Exception as e:
        results.append({"subsystem": "Database Pristine Zero-Data State", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 3. Tier 2 Frictionless OSINT Clearance Check
    t0 = time.time()
    try:
        url = "http://127.0.0.1:8000/api/authorizations/check?target=curezy.in&scope=PASSIVE_OSINT"
        with urllib.request.urlopen(url) as res:
            data = json.loads(res.read().decode())
            dur = (time.time() - t0) * 1000
            authorized = data.get("authorized", False)
            results.append({
                "subsystem": "Tier 2 Frictionless OSINT Clearance",
                "status": "PASS" if authorized else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"Target: curezy.in, Scope: {data.get('permitted_scope')}, Method: {data.get('authorization_id')}"
            })
    except Exception as e:
        results.append({"subsystem": "Tier 2 Frictionless OSINT Clearance", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 4. RFC 8655 Active Scope Guard & Anti-SSRF Check
    t0 = time.time()
    try:
        # Active scan without TXT should be blocked for unverified domain
        url = "http://127.0.0.1:8000/api/authorizations/check?target=unverified-target-domain.com&scope=FULL_ACTIVE"
        with urllib.request.urlopen(url) as res:
            data = json.loads(res.read().decode())
            dur = (time.time() - t0) * 1000
            # Active scan must NOT be authorized without challenge
            results.append({
                "subsystem": "RFC 8655 Scope Enforcement",
                "status": "PASS" if not data.get("authorized") else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"Unverified target active probing blocked (authorized={data.get('authorized')})"
            })
    except Exception as e:
        results.append({"subsystem": "RFC 8655 Scope Enforcement", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 5. Autonomous Defense Synthesis Check
    t0 = time.time()
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/defense/generate-rule",
            data=json.dumps({"cve_id": "CVE-2024-4577", "target_domain": "curezy.in"}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            dur = (time.time() - t0) * 1000
            has_waf = bool(data.get("cloudflare_waf") and data.get("modsecurity_nginx") and data.get("iptables_firewall"))
            results.append({
                "subsystem": "Autonomous Multi-Layer Defense Synthesis",
                "status": "PASS" if has_waf else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"Synthesized CF WAF, ModSec, iptables, & patch rules for {data.get('cve_id')}"
            })
    except Exception as e:
        results.append({"subsystem": "Autonomous Multi-Layer Defense Synthesis", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 6. Diagnostic Micro-Probe Verifier Check
    t0 = time.time()
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/defense/verify",
            data=json.dumps({"url": "https://curezy.in/cgi-bin/php-cgi?%add+allow_url_include=1", "expected_status": 403}).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode())
            dur = (time.time() - t0) * 1000
            probe_operational = (res.status == 200 and "verdict" in data and "status_code" in data)
            results.append({
                "subsystem": "Diagnostic Micro-Probe Verification",
                "status": "PASS" if probe_operational else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"Target Status: HTTP {data.get('status_code')} | Diagnostic Verdict: {data.get('verdict')} ({data.get('latency_ms')}ms)"
            })
    except Exception as e:
        results.append({"subsystem": "Diagnostic Micro-Probe Verification", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 7. Executive PDF Report Download Check
    t0 = time.time()
    try:
        url = "http://127.0.0.1:8000/api/scans/reports/latest/download?target=curezy.in"
        with urllib.request.urlopen(url) as res:
            pdf_bytes = res.read()
            dur = (time.time() - t0) * 1000
            disp = res.headers.get("Content-Disposition", "")
            is_valid_pdf = pdf_bytes.startswith(b"%PDF-") and ("attachment" in disp)
            results.append({
                "subsystem": "Executive PDF ReportLab Engine",
                "status": "PASS" if is_valid_pdf else "FAIL",
                "latency_ms": round(dur, 2),
                "detail": f"PDF generated ({len(pdf_bytes)} bytes) with Content-Disposition: attachment"
            })
    except Exception as e:
        results.append({"subsystem": "Executive PDF ReportLab Engine", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # 8. Metasploit Weaponization Correlation Check
    t0 = time.time()
    try:
        from backend.services.vulnerability_service import KNOWN_METASPLOIT_MODULES
        has_php_cgi = "CVE-2024-4577" in KNOWN_METASPLOIT_MODULES
        msf_mod = KNOWN_METASPLOIT_MODULES["CVE-2024-4577"]["module"]
        dur = (time.time() - t0) * 1000
        results.append({
            "subsystem": "Metasploit Weaponization Registry",
            "status": "PASS" if has_php_cgi else "FAIL",
            "latency_ms": round(dur, 2),
            "detail": f"CVE-2024-4577 -> {msf_mod} (0.40x Dijkstra friction factor)"
        })
    except Exception as e:
        results.append({"subsystem": "Metasploit Weaponization Registry", "status": "FAIL", "latency_ms": 0, "detail": str(e)})

    # Output formatted report
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_audit()
