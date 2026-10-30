#!/usr/bin/env python3
"""
DRISHTI — SQLite to Supabase PostgreSQL Data Migration Script
Transfers all existing scans, findings, authorizations, audit events, and passive observations
from SQLite into Supabase PostgreSQL with data integrity validation, sequence synchronization,
and verification reporting.
"""

import argparse
import asyncio
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from dotenv import load_dotenv

# Load local environment if available
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

TABLE_ORDER = [
    ("threat_indicators", "id"),
    ("consent_domains", "domain"),
    ("authorizations", "id"),
    ("scans", "id"),
    ("scan_findings", "id"),
    ("audit_events", "id"),
    ("passive_observations", "id"),
    ("vulnerabilities", "cve_id"),
    ("asset_fingerprints", "id"),
    ("vulnerability_findings", "id"),
    ("vulnerability_sync_checkpoints", "source"),
]

SERIAL_TABLES = [
    "threat_indicators",
    "scan_findings",
    "audit_events",
    "passive_observations",
    "asset_fingerprints",
    "vulnerability_findings",
]

TIMESTAMP_COLS = {
    "created_at",
    "updated_at",
    "completed_at",
    "verified_at",
    "expires_at",
    "revoked_at",
    "first_seen",
    "observed_at",
    "cached_at",
    "published_at",
    "last_modified_at",
    "evaluated_at",
    "last_sync_timestamp",
}


def parse_db_timestamp(val: Any) -> Any:
    """Parses SQLite string timestamps to Python datetime for PostgreSQL TIMESTAMPTZ."""
    if val is None or not isinstance(val, str):
        return val
    try:
        s = val.strip()
        # Handle '2026-10-20 09:18:12' format by replacing space
        if " " in s and "T" not in s:
            s = s.replace(" ", "T")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return val


def read_sqlite_table(db_path: Path, table_name: str) -> Tuple[List[str], List[Tuple[Any, ...]]]:
    """Reads all rows and column names from an SQLite table."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Check if table exists
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    if not cur.fetchone():
        conn.close()
        return [], []

    cur.execute(f"PRAGMA table_info({table_name});")
    cols = [r[1] for r in cur.fetchall()]

    cur.execute(f"SELECT {', '.join(cols)} FROM {table_name};")
    rows = cur.fetchall()
    conn.close()
    return cols, rows


async def migrate_data(
    sqlite_path: Path,
    pg_dsn: str,
    dry_run: bool = False,
    apply_schema: bool = True
) -> Dict[str, Dict[str, Any]]:
    """Migrates data from SQLite to PostgreSQL with verification."""
    import asyncpg

    print(f"[*] Connecting to SQLite database at: {sqlite_path}")
    if not sqlite_path.exists():
        raise FileNotFoundError(f"SQLite database not found at {sqlite_path}")

    # Inspect SQLite summary
    summary: Dict[str, Dict[str, Any]] = {}
    total_sqlite_records = 0
    for tbl, _ in TABLE_ORDER:
        cols, rows = read_sqlite_table(sqlite_path, tbl)
        summary[tbl] = {"cols": cols, "sqlite_count": len(rows), "pg_count": 0, "status": "PENDING"}
        total_sqlite_records += len(rows)

    print(f"[*] Found {total_sqlite_records} total records across {len(TABLE_ORDER)} tables in SQLite.")
    for tbl, data in summary.items():
        print(f"    - {tbl:<22}: {data['sqlite_count']} rows")

    if dry_run:
        print("\n[!] Dry run enabled — skipping PostgreSQL write.")
        for tbl in summary:
            summary[tbl]["status"] = "DRY_RUN_OK"
        return summary

    print(f"\n[*] Connecting to PostgreSQL / Supabase...")
    # Normalize postgres:// to postgresql:// if needed for asyncpg
    clean_dsn = pg_dsn
    if clean_dsn.startswith("postgres://"):
        clean_dsn = "postgresql://" + clean_dsn[len("postgres://"):]

    # Remove incompatible async driver prefix if present
    clean_dsn = clean_dsn.replace("postgresql+asyncpg://", "postgresql://")

    # Connect with SSL fallback for Supabase
    try:
        conn = await asyncpg.connect(clean_dsn, ssl="require", timeout=15)
    except Exception:
        try:
            conn = await asyncpg.connect(clean_dsn, timeout=15)
        except Exception as e:
            print(f"[!] Failed to connect to PostgreSQL: {e}")
            raise

    try:
        # Apply all schema migrations in order
        if apply_schema:
            migrations_dir = Path(__file__).resolve().parent.parent / "data" / "migrations"
            if migrations_dir.exists():
                for schema_file in sorted(migrations_dir.glob("*.sql")):
                    print(f"[*] Applying schema migration from: {schema_file.name}")
                    ddl = schema_file.read_text(encoding="utf-8")
                    await conn.execute(ddl)
                    print(f"    Applied {schema_file.name} successfully.")

        # Migrate each table in dependency order
        for tbl, pk_col in TABLE_ORDER:
            cols, rows = read_sqlite_table(sqlite_path, tbl)
            if not rows:
                print(f"[*] Skipping {tbl} (0 rows)")
                continue

            print(f"[*] Migrating {len(rows)} records into '{tbl}'...")
            col_list_str = ", ".join(cols)
            placeholders = ", ".join(f"${i+1}" for i in range(len(cols)))

            # Build idempotent UPSERT statement
            update_clauses = [f"{c} = EXCLUDED.{c}" for c in cols if c != pk_col]
            if update_clauses:
                conflict_action = f"DO UPDATE SET {', '.join(update_clauses)}"
            else:
                conflict_action = "DO NOTHING"

            insert_sql = f"""
                INSERT INTO {tbl} ({col_list_str})
                VALUES ({placeholders})
                ON CONFLICT ({pk_col}) {conflict_action}
            """

            # Batch insert rows in chunks of 200
            chunk_size = 200
            for i in range(0, len(rows), chunk_size):
                chunk = rows[i:i + chunk_size]
                # Format parameters safely (convert ISO datetime string representations if needed)
                clean_chunk = []
                for r in chunk:
                    clean_row = []
                    for col_name, val in zip(cols, r):
                        if col_name in TIMESTAMP_COLS and val is not None:
                            clean_row.append(parse_db_timestamp(val))
                        else:
                            clean_row.append(val)
                    clean_chunk.append(tuple(clean_row))

                await conn.executemany(insert_sql, clean_chunk)

            # Synchronize BIGSERIAL sequences if table has an autoincrement ID
            if tbl in SERIAL_TABLES:
                seq_sql = f"""
                    SELECT setval(
                        pg_get_serial_sequence('{tbl}', 'id'),
                        COALESCE((SELECT MAX(id) FROM {tbl}), 1),
                        true
                    );
                """
                try:
                    await conn.execute(seq_sql)
                except Exception as seq_err:
                    print(f"    [!] Warning: Failed to reset sequence for {tbl}: {seq_err}")

        # Verification pass: count rows in PostgreSQL
        print("\n[*] Verifying data migration row counts...")
        for tbl, pk_col in TABLE_ORDER:
            try:
                pg_count = await conn.fetchval(f"SELECT COUNT(*) FROM {tbl};")
                summary[tbl]["pg_count"] = pg_count
                if pg_count >= summary[tbl]["sqlite_count"]:
                    summary[tbl]["status"] = "VERIFIED_OK"
                else:
                    summary[tbl]["status"] = "COUNT_MISMATCH"
            except Exception as cnt_err:
                summary[tbl]["pg_count"] = -1
                summary[tbl]["status"] = f"ERROR: {cnt_err}"

    finally:
        await conn.close()

    return summary


def main():
    parser = argparse.ArgumentParser(description="DRISHTI SQLite to Supabase PostgreSQL Migration")
    parser.add_argument("--sqlite", type=Path, default=Path("data/drishti.db"), help="Path to source SQLite database")
    parser.add_argument("--postgres", type=str, default=os.getenv("DATABASE_URL"), help="PostgreSQL connection string")
    parser.add_argument("--dry-run", action="store_true", help="Inspect without writing to PostgreSQL")
    parser.add_argument("--skip-schema", action="store_true", help="Skip running 001_initial_schema.sql")

    args = parser.parse_args()

    sqlite_path = args.sqlite.resolve()
    if not sqlite_path.exists():
        # Try finding it relative to project root
        project_root = Path(__file__).resolve().parent.parent
        alt_path = project_root / args.sqlite
        if alt_path.exists():
            sqlite_path = alt_path

    if not args.dry_run and not args.postgres:
        print("[!] Error: --postgres or DATABASE_URL environment variable must be specified.")
        print("    Example: python scripts/migrate_sqlite_to_postgres.py --postgres \"postgresql://postgres:pass@db.supabase.co:5432/postgres\"")
        print("    Or run with --dry-run to inspect SQLite data.")
        sys.exit(1)

    print("=================================================================")
    print("      DRISHTI SQLite -> Supabase PostgreSQL Data Migration       ")
    print("=================================================================")

    try:
        results = asyncio.run(migrate_data(
            sqlite_path=sqlite_path,
            pg_dsn=args.postgres or "",
            dry_run=args.dry_run,
            apply_schema=not args.skip_schema
        ))

        print("\n======================= Migration Report =======================")
        print(f"{'Table':<24} | {'SQLite Rows':<12} | {'Postgres Rows':<14} | {'Status'}")
        print("-" * 65)
        all_passed = True
        for tbl, data in results.items():
            print(f"{tbl:<24} | {data['sqlite_count']:<12} | {data['pg_count']:<14} | {data['status']}")
            if "ERROR" in data['status'] or data['status'] == "COUNT_MISMATCH":
                all_passed = False

        print("================================================================")
        if all_passed:
            print("[+] Data migration completed successfully!")
            sys.exit(0)
        else:
            print("[!] Migration completed with warnings or mismatches.")
            sys.exit(2)
    except Exception as ex:
        print(f"\n[!] Migration failed with error: {ex}")
        sys.exit(1)


if __name__ == "__main__":
    main()
