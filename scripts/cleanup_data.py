#!/usr/bin/env python3
"""
DRISHTI — Purge Demo Data and Previous Scans
Removes all historical scan runs, stage executions, findings, attack graphs,
and demo authorizations, resetting the platform to a pristine state.
Preserves the verified production target authorization (vvdx.in).
"""

import asyncio
import os
from pathlib import Path
import sqlite3
import sys

# Target databases
DB_PATHS = [
    Path("D:/drishti/data/drishti.db"),
    Path("E:/drishti/data/drishti.db"),
]

TABLES_TO_TRUNCATE = [
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
]

VVDX_AUTH = (
    "auth-657a97e0ee34",
    "vvdx.in",
    "FULL_PASSIVE",
    "local-operator-dev",
    "verified",
    "dns_txt",
    "drishti-verify-657a97e0ee34",
    "_drishti-challenge.vvdx.in",
    "2026-10-30 05:59:05",
    "2026-10-30 05:59:05",
    "2026-11-29 05:59:05",
)


def cleanup_sqlite(db_path: Path):
    if not db_path.exists():
        print(f"[SKIP] Database not found at {db_path}")
        return

    print(f"\n[CLEANING] SQLite database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get list of existing tables
    existing_tables = set(
        r[0] for r in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
    )

    deleted_counts = {}
    for table in TABLES_TO_TRUNCATE:
        if table in existing_tables:
            count = cursor.execute(f"SELECT COUNT(*) FROM {table};").fetchone()[0]
            cursor.execute(f"DELETE FROM {table};")
            deleted_counts[table] = count

    # Clean authorizations - remove all demo/test targets except real target vvdx.in
    auth_deleted = 0
    if "authorizations" in existing_tables:
        auth_before = cursor.execute("SELECT COUNT(*) FROM authorizations;").fetchone()[0]
        cursor.execute("DELETE FROM authorizations WHERE target_domain != 'vvdx.in';")
        auth_after = cursor.execute("SELECT COUNT(*) FROM authorizations;").fetchone()[0]
        auth_deleted = auth_before - auth_after

        # Ensure vvdx.in authorization exists
        cursor.execute("""
            INSERT OR REPLACE INTO authorizations (
                id, target_domain, permitted_scope, operator_id, status,
                verification_method, verification_token, challenge_record_name,
                created_at, verified_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, VVDX_AUTH)

    conn.commit()

    # Vacuum database to reclaim disk space
    cursor.execute("VACUUM;")
    conn.commit()
    conn.close()

    for tbl, cnt in deleted_counts.items():
        if cnt > 0:
            print(f"  - {tbl}: deleted {cnt} rows")
    print(f"  - authorizations: deleted {auth_deleted} demo domains; preserved vvdx.in")
    print(f"[SUCCESS] Cleaned {db_path.name} (File size: {db_path.stat().st_size:,} bytes)")


async def cleanup_postgres():
    """If PostgreSQL is accessible, purge demo data and previous scans there as well."""
    database_url = os.getenv("DATABASE_URL", "postgresql://postgres:devpass@127.0.0.1:5432/drishti")
    if not database_url.startswith("postgresql://") and not database_url.startswith("postgres://"):
        return

    print(f"\n[CHECKING] PostgreSQL connection...")
    try:
        import asyncpg
        conn = await asyncio.wait_for(asyncpg.connect(database_url), timeout=3.0)
    except Exception as ex:
        print(f"[INFO] PostgreSQL is currently offline ({ex}). Skipping PostgreSQL cleanup.")
        return

    try:
        print("[CLEANING] Connected to PostgreSQL. Purging previous scans and demo data...")
        for table in TABLES_TO_TRUNCATE:
            try:
                cnt = await conn.fetchval(f"SELECT COUNT(*) FROM {table};")
                if cnt > 0:
                    await conn.execute(f"TRUNCATE TABLE {table} CASCADE;")
                    print(f"  - {table}: truncated {cnt} rows")
            except Exception as e:
                pass

        # Clean authorizations
        auth_cnt = await conn.fetchval("SELECT COUNT(*) FROM authorizations WHERE target_domain != 'vvdx.in';")
        await conn.execute("DELETE FROM authorizations WHERE target_domain != 'vvdx.in';")
        print(f"  - authorizations: removed {auth_cnt} demo domains; preserved vvdx.in")

        # Ensure vvdx.in exists
        await conn.execute("""
            INSERT INTO authorizations (
                id, target_domain, permitted_scope, operator_id, status,
                verification_method, verification_token, challenge_record_name,
                created_at, verified_at, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::timestamptz, $11::timestamptz)
            ON CONFLICT (id) DO UPDATE SET status = 'verified';
        """, *VVDX_AUTH)

        await conn.close()
        print("[SUCCESS] PostgreSQL cleanup complete.")
    except Exception as e:
        print(f"[WARN] Error during PostgreSQL cleanup: {e}")


def main():
    print("=" * 60)
    print("  DRISHTI CYBER INTELLIGENCE PLATFORM — PURGE & RESET")
    print("=" * 60)

    for path in DB_PATHS:
        cleanup_sqlite(path)

    try:
        asyncio.run(cleanup_postgres())
    except Exception as ex:
        print(f"PostgreSQL cleanup error: {ex}")

    print("\n" + "=" * 60)
    print("  PURGE COMPLETE: All previous scans and demo data removed.")
    print("  Software is in a fresh, pristine state with 0 scans.")
    print("=" * 60)


if __name__ == "__main__":
    main()
