import pytest
from pathlib import Path
from httpx import ASGITransport, AsyncClient
from backend.main import app
from backend.db.database import (
    adapt_sqlite_query_to_postgres,
    PostgresRowAdapter,
    PostgresCursorContext,
    get_db_status,
    init_db
)
from scripts.migrate_sqlite_to_postgres import read_sqlite_table, migrate_data


def test_sql_adaptation_to_postgres():
    """Verifies that SQLite queries are correctly translated to PostgreSQL syntax."""
    # 1. Parameter placeholder translation
    q1 = "SELECT * FROM scans WHERE target = ? AND status = ?"
    adapted1 = adapt_sqlite_query_to_postgres(q1)
    assert adapted1 == "SELECT * FROM scans WHERE target = $1 AND status = $2"

    # 2. INSERT OR IGNORE translation
    q2 = "INSERT OR IGNORE INTO threat_indicators (indicator_type, value, confidence) VALUES (?, ?, ?)"
    adapted2 = adapt_sqlite_query_to_postgres(q2)
    assert "INSERT INTO" in adapted2
    assert "ON CONFLICT DO NOTHING" in adapted2
    assert "$1, $2, $3" in adapted2

    # 3. Date functions translation
    q3 = "INSERT INTO authorizations (id, expires_at) VALUES (?, datetime('now', '+30 days'))"
    adapted3 = adapt_sqlite_query_to_postgres(q3)
    assert "NOW() + INTERVAL '30 days'" in adapted3
    assert "$1" in adapted3

    # 4. CURRENT_TIMESTAMP translation
    q4 = "UPDATE scans SET updated_at = CURRENT_TIMESTAMP WHERE id = ?"
    adapted4 = adapt_sqlite_query_to_postgres(q4)
    assert "NOW()" in adapted4
    assert "$1" in adapted4


def test_postgres_ddl_schema_completeness():
    """Validates 001_initial_schema.sql contains all required tables, types, and constraints."""
    schema_path = Path(__file__).resolve().parent.parent / "data" / "migrations" / "001_initial_schema.sql"
    assert schema_path.exists(), "001_initial_schema.sql must exist"
    ddl = schema_path.read_text(encoding="utf-8")

    required_tables = [
        "threat_indicators",
        "scans",
        "scan_findings",
        "consent_domains",
        "authorizations",
        "audit_events",
        "passive_observations",
    ]
    for table in required_tables:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl, f"Missing table {table} in DDL"

    # Foreign key and cascade checks
    assert "ON DELETE CASCADE" in ddl
    assert "TIMESTAMPTZ" in ddl
    assert "BIGSERIAL" in ddl


def test_postgres_row_adapter():
    """Verifies PostgresRowAdapter seamlessly supports dict(row), indexing, and key access."""
    sample_data = {"id": "scan-123", "target": "example.com", "progress": 100}
    adapter = PostgresRowAdapter(sample_data)

    # Key lookup
    assert adapter["id"] == "scan-123"
    assert adapter["target"] == "example.com"
    assert adapter.get("missing", 42) == 42

    # Dict conversion
    converted = dict(adapter)
    assert converted == sample_data

    # Iteration and length
    assert len(adapter) == 3
    assert "target" in adapter


@pytest.mark.asyncio
async def test_sqlite_data_inspection_and_dry_run_migration():
    """Verifies that the migration script correctly inspects SQLite and produces a dry run report."""
    sqlite_path = Path(__file__).resolve().parent.parent / "data" / "drishti.db"
    assert sqlite_path.exists()

    # Read table helper
    cols, rows = read_sqlite_table(sqlite_path, "scans")
    assert "id" in cols
    assert "target" in cols
    if len(rows) == 0:
        import sqlite3
        con = sqlite3.connect(sqlite_path)
        con.execute("INSERT OR IGNORE INTO scans (id, target, status, progress, current_step) VALUES ('test-sample-scan', 'target.corp', 'completed', 100, 'Completed')")
        con.commit()
        con.close()
        cols, rows = read_sqlite_table(sqlite_path, "scans")
    assert len(rows) > 0

    # Dry run migration
    report = await migrate_data(
        sqlite_path=sqlite_path,
        pg_dsn="",
        dry_run=True,
        apply_schema=False
    )
    assert "scans" in report
    assert "scan_findings" in report
    assert "authorizations" in report
    assert report["scans"]["status"] == "DRY_RUN_OK"
    assert report["scans"]["sqlite_count"] > 0


@pytest.mark.asyncio
async def test_health_reports_database_status():
    """Verifies that /health endpoint provides database diagnostics and latency."""
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert "database" in data
        assert data["database"]["engine"] in ("sqlite", "postgresql")
        assert "latency_ms" in data["database"]
        assert data["status"] == "operational"
