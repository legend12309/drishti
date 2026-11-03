#!/usr/bin/env python3
"""
DRISHTI — Complete Data Purge
Removes all historical scans, findings, stages, observations, graph snapshots,
attack paths, risk assessments, reports, audit events, and authorizations.
Resets the software to pristine, brand-new state.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(r"D:\drishti\data\drishti.db")

TABLES_TO_PURGE = [
    "scan_reports",
    "scan_stages",
    "active_port_observations",
    "http_service_observations",
    "zap_alert_observations",
    "trivy_findings",
    "nuclei_findings",
    "mitigation_simulations",
    "attack_paths",
    "risk_assessments",
    "graph_snapshots",
    "vulnerability_findings",
    "asset_fingerprints",
    "passive_observations",
    "scan_findings",
    "scans",
    "audit_events",
    "threat_indicators",
    "consent_domains",
    "authorizations",
]

def main():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    existing_tables = set(
        r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
    )

    print("Purging all tables...")
    for table in TABLES_TO_PURGE:
        if table in existing_tables:
            before = cur.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
            cur.execute(f"DELETE FROM {table};")
            print(f"  [PURGED] {table}: {before} -> 0 rows")

    conn.commit()
    print("Reclaiming storage via VACUUM...")
    cur.execute("VACUUM;")
    conn.close()
    print("[OK] DRISHTI database reset to 100% pristine brand-new state.")

if __name__ == "__main__":
    main()
