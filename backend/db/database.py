import asyncio
import logging
import os
import re
import time

logger = logging.getLogger("drishti.database")
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union
from dotenv import load_dotenv

# Ensure environment variables are loaded from project root .env
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")
load_dotenv()

from datetime import datetime, timezone

def normalize_pg_param(param: Any) -> Any:
    """Normalizes string ISO dates to Python datetime instances for asyncpg."""
    if isinstance(param, str) and len(param) >= 19:
        if param[4] == '-' and param[7] == '-':
            try:
                s = param.strip().replace(" ", "T")
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                pass
    return param


def normalize_pg_params(params: tuple) -> tuple:
    return tuple(normalize_pg_param(p) for p in params)

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DB_PATH = DATA_DIR / "drishti.db"

# Database connection settings
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")).strip()


_postgres_active: Optional[bool] = None

def is_postgres_enabled() -> bool:
    """Returns True if a PostgreSQL / Supabase connection URL is configured and active."""
    global _postgres_active
    if _postgres_active is False:
        return False
    return bool(DATABASE_URL and (
        DATABASE_URL.startswith("postgresql://")
        or DATABASE_URL.startswith("postgres://")
        or DATABASE_URL.startswith("postgresql+asyncpg://")
    ))


def get_clean_pg_url(url: str) -> str:
    """Cleans and standardizes PostgreSQL URL for asyncpg."""
    clean = url.strip()
    if clean.startswith("postgres://"):
        clean = "postgresql://" + clean[len("postgres://"):]
    clean = clean.replace("postgresql+asyncpg://", "postgresql://")
    return clean


def adapt_sqlite_query_to_postgres(query: str) -> str:
    """
    Transparently converts SQLite SQL syntax and ? parameter placeholders
    to PostgreSQL $1, $2... placeholders and PostgreSQL dialect conventions.
    """
    sql = query.strip()

    # 1. Convert datetime('now', '+30 days') to NOW() + INTERVAL '30 days'
    sql = re.sub(
        r"datetime\(\s*'now'\s*,\s*'\+(\d+)\s+days'\s*\)",
        r"NOW() + INTERVAL '\1 days'",
        sql,
        flags=re.IGNORECASE
    )
    # 2. Convert CURRENT_TIMESTAMP to NOW() where appropriate
    sql = re.sub(r"\bCURRENT_TIMESTAMP\b", "NOW()", sql, flags=re.IGNORECASE)

    # 3. Convert INSERT OR IGNORE INTO
    if re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", sql, flags=re.IGNORECASE):
        sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.IGNORECASE)
        if "ON CONFLICT" not in sql.upper():
            sql = f"{sql} ON CONFLICT DO NOTHING"

    # 4. Convert INSERT OR REPLACE INTO for common tables
    if re.search(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", sql, flags=re.IGNORECASE):
        sql = re.sub(r"\bINSERT\s+OR\s+REPLACE\s+INTO\b", "INSERT INTO", sql, flags=re.IGNORECASE)
        if "ON CONFLICT" not in sql.upper():
            # Extract target table name
            m = re.search(r"INSERT\s+INTO\s+([a-zA-Z0-9_]+)", sql, flags=re.IGNORECASE)
            if m:
                tbl = m.group(1).lower()
                pk = "domain" if tbl == "consent_domains" else "id"
                # Exclude PK from update on conflict
                sql = f"{sql} ON CONFLICT ({pk}) DO NOTHING"

    # 5. Convert ? positional placeholders to $1, $2, $3...
    if "?" in sql:
        parts = sql.split("?")
        new_sql = []
        for i, part in enumerate(parts[:-1]):
            new_sql.append(part)
            new_sql.append(f"${i + 1}")
        new_sql.append(parts[-1])
        sql = "".join(new_sql)

    return sql


# ---------------------------------------------------------------------------
# PostgreSQL Row & Cursor Adapter for 100% SQLite Caller Compatibility
# ---------------------------------------------------------------------------

class PostgresRowAdapter:
    """Wraps an asyncpg Record to provide dict-like and index-based access."""
    def __init__(self, record: Any):
        self._record = record
        self._dict = dict(record) if record is not None else {}

    def __getitem__(self, key: Union[str, int]) -> Any:
        if isinstance(key, int):
            return self._record[key]
        return self._dict.get(key)

    def get(self, key: str, default: Any = None) -> Any:
        return self._dict.get(key, default)

    def keys(self):
        return self._dict.keys()

    def values(self):
        return self._dict.values()

    def items(self):
        return self._dict.items()

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def __iter__(self):
        return iter(self._dict.items())

    def __len__(self) -> int:
        return len(self._dict)

    def __repr__(self) -> str:
        return f"PostgresRowAdapter({self._dict})"


class PostgresCursorContext:
    """Simulates an async cursor context manager for asyncpg queries."""
    def __init__(self, records: List[Any], last_row_id: int = 1):
        self._records = [PostgresRowAdapter(r) for r in records]
        self._idx = 0
        self.lastrowid = last_row_id

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    async def fetchone(self) -> Optional[PostgresRowAdapter]:
        if self._idx < len(self._records):
            row = self._records[self._idx]
            self._idx += 1
            return row
        return None

    async def fetchall(self) -> List[PostgresRowAdapter]:
        rem = self._records[self._idx:]
        self._idx = len(self._records)
        return rem


class PostgresConnectionAdapter:
    """Wraps an asyncpg connection to match aiosqlite interface seamlessly."""
    def __init__(self, conn: Any):
        self._conn = conn
        self.row_factory = None  # Compatible attribute assignment

    def execute(self, query: str, params: tuple = ()) -> PostgresCursorContext:
        """Adapts query and executes, returning an async cursor context."""
        async def _exec():
            adapted_sql = adapt_sqlite_query_to_postgres(query)
            clean_params = normalize_pg_params(params)
            try:
                # If query is a SELECT or has RETURNING, fetch rows
                if adapted_sql.strip().upper().startswith(("SELECT", "WITH")) or "RETURNING" in adapted_sql.upper():
                    records = await self._conn.fetch(adapted_sql, *clean_params)
                    return PostgresCursorContext(records)
                else:
                    # DML statement (INSERT / UPDATE / DELETE)
                    status = await self._conn.execute(adapted_sql, *clean_params)
                    return PostgresCursorContext([], last_row_id=1)
            except Exception as e:
                raise e

        # We return a lazy or awaitable context manager
        return AsyncCursorRunner(_exec())

    async def commit(self):
        # asyncpg executes autocommit per statement outside explicit transactions
        pass

    async def close(self):
        pass


class AsyncCursorRunner:
    """Allows 'async with db.execute(sql, params) as cursor:' syntax on Postgres."""
    def __init__(self, coro):
        self._coro = coro
        self._cursor = None

    def __await__(self):
        return self._coro.__await__()

    async def __aenter__(self) -> PostgresCursorContext:
        self._cursor = await self._coro
        return self._cursor

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


# ---------------------------------------------------------------------------
# Global Connection Pool Manager for PostgreSQL
# ---------------------------------------------------------------------------

class PostgresPoolManager:
    """Manages an asyncpg connection pool with cloud network hardening and automatic loop recovery."""
    def __init__(self, dsn: str):
        self.dsn = get_clean_pg_url(dsn)
        self._pool = None
        self._lock = asyncio.Lock()

    async def get_pool(self):
        current_loop = asyncio.get_running_loop()
        needs_new_pool = (
            self._pool is None
            or getattr(self._pool, "_closed", True)
            or getattr(self._pool, "_loop", None) != current_loop
            or (getattr(self._pool, "_loop", None) and self._pool._loop.is_closed())
        )
        if needs_new_pool:
            import asyncpg
            # Hardened for cloud latency & Supabase Supavisor / PgBouncer resilience:
            # - pool_size=10, max_size=20
            # - statement_cache_size=0 (prevents prepared statement collision in Transaction Mode)
            # - max_inactive_connection_lifetime=1800.0 (pool_recycle=1800)
            # - command_timeout=30.0
            server_settings = {"statement_cache_size": "0"} if ":6543" in self.dsn else {}
            try:
                self._pool = await asyncpg.create_pool(
                    self.dsn,
                    min_size=2,
                    max_size=20,
                    ssl="require",
                    command_timeout=30.0,
                    max_inactive_connection_lifetime=1800.0,
                    statement_cache_size=0 if ":6543" in self.dsn else 100,
                )
            except Exception:
                self._pool = await asyncpg.create_pool(
                    self.dsn,
                    min_size=2,
                    max_size=20,
                    command_timeout=30.0,
                    max_inactive_connection_lifetime=1800.0,
                    statement_cache_size=0 if ":6543" in self.dsn else 100,
                )
        return self._pool

    async def close(self):
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


pg_pool_manager: Optional[PostgresPoolManager] = (
    PostgresPoolManager(DATABASE_URL) if is_postgres_enabled() else None
)


# ---------------------------------------------------------------------------
# SQLite Single-Writer Database Queue (Fallback / Hermetic Local Mode)
# ---------------------------------------------------------------------------

@dataclass
class WriteTask:
    query: str
    params: tuple
    future: asyncio.Future


class DatabaseQueue:
    """
    Unified database write handler.
    If PostgreSQL is configured: routes writes directly to connection pool.
    If SQLite is configured: queues writes through single-writer worker for WAL safety.
    """
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._queue: Optional[asyncio.Queue[Optional[WriteTask]]] = None
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self):
        if is_postgres_enabled():
            # Initialize PG pool
            if pg_pool_manager:
                await pg_pool_manager.get_pool()
            return

        import aiosqlite
        current_loop = asyncio.get_running_loop()
        needs_restart = (
            self._worker_task is None
            or self._worker_task.done()
            or self._queue is None
        )
        if not needs_restart:
            try:
                if self._worker_task.get_loop() != current_loop:
                    needs_restart = True
            except Exception:
                needs_restart = True

        if needs_restart:
            self._queue = asyncio.Queue()
            self._worker_task = current_loop.create_task(self._writer_loop())

    async def _writer_loop(self):
        import aiosqlite
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute("PRAGMA busy_timeout=5000;")
            while True:
                if self._queue is None:
                    break
                task = await self._queue.get()
                if task is None:
                    break
                try:
                    cursor = await db.execute(task.query, task.params)
                    ret_val = cursor.lastrowid
                    if "RETURNING" in task.query.upper():
                        row = await cursor.fetchone()
                        if row:
                            ret_val = row[0]
                        await cursor.close()
                    await db.commit()
                    if not task.future.done():
                        task.future.set_result(ret_val)
                except Exception as ex:
                    if not task.future.done():
                        task.future.set_exception(ex)
                finally:
                    self._queue.task_done()

    async def execute_write(self, query: str, params: tuple = ()) -> Any:
        global _postgres_active
        if is_postgres_enabled() and pg_pool_manager:
            try:
                pool = await pg_pool_manager.get_pool()
                async with pool.acquire() as conn:
                    adapted_sql = adapt_sqlite_query_to_postgres(query)
                    clean_params = normalize_pg_params(params)
                    # If statement has RETURNING id, return fetched value
                    if "RETURNING" in adapted_sql.upper():
                        res = await conn.fetchval(adapted_sql, *clean_params)
                        return res or 1
                    await conn.execute(adapted_sql, *clean_params)
                    return 1
            except Exception as pg_err:
                logger.warning(f"PostgreSQL execute_write failed ({pg_err}). Falling back to SQLite.")
                _postgres_active = False

        # SQLite fallback execution
        await self.start()
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        if self._queue is not None:
            await self._queue.put(WriteTask(query=query, params=params, future=future))
        return await future

    async def execute_bulk_write(self, query: str, param_list: List[tuple]) -> int:
        """
        Executes a high-efficiency single-trip bulk write or upsert across records.
        Minimizes WAN latency (e.g. 229ms round-trip to cloud PostgreSQL).
        """
        global _postgres_active
        if not param_list:
            return 0
        if is_postgres_enabled() and pg_pool_manager:
            try:
                pool = await pg_pool_manager.get_pool()
                async with pool.acquire() as conn:
                    adapted_sql = adapt_sqlite_query_to_postgres(query)
                    clean_param_list = [normalize_pg_params(p) for p in param_list]
                    await conn.executemany(adapted_sql, clean_param_list)
                    return len(clean_param_list)
            except Exception as pg_err:
                logger.warning(f"PostgreSQL bulk write failed ({pg_err}). Falling back to SQLite.")
                _postgres_active = False

        # SQLite fallback execution
        await self.start()
        for p in param_list:
            await self.execute_write(query, p)
        return len(param_list)


db_queue = DatabaseQueue(DB_PATH)


# ---------------------------------------------------------------------------
# get_db Context Manager: Provides Uniform Connection Object
# ---------------------------------------------------------------------------

@asynccontextmanager
async def get_db() -> AsyncGenerator[Any, None]:
    """
    Context manager for database connections.
    Yields PostgresConnectionAdapter when PostgreSQL is enabled,
    or aiosqlite.Connection when SQLite is enabled.
    """
    global _postgres_active
    if is_postgres_enabled() and pg_pool_manager:
        try:
            pool = await pg_pool_manager.get_pool()
            async with pool.acquire() as conn:
                adapter = PostgresConnectionAdapter(conn)
                yield adapter
            return
        except Exception as pg_err:
            logger.warning(f"PostgreSQL connection acquire failed ({pg_err}). Falling back to SQLite.")
            _postgres_active = False

    # SQLite fallback
    import aiosqlite
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA synchronous=NORMAL;")
        await db.execute("PRAGMA busy_timeout=5000;")
        yield db


# ---------------------------------------------------------------------------
# init_db: Automated Schema Setup, Seed Data & Recovery Handling
# ---------------------------------------------------------------------------

async def init_db():
    """Initializes tables, indexes, demo seed data, and recovery routines."""
    global _postgres_active
    if is_postgres_enabled() and pg_pool_manager:
        try:
            pool = await pg_pool_manager.get_pool()
            async with pool.acquire() as conn:
                # Apply PostgreSQL initial schema migration
                schema_file = DATA_DIR / "migrations" / "001_initial_schema.sql"
                if schema_file.exists():
                    ddl = schema_file.read_text(encoding="utf-8")
                    await conn.execute(ddl)

                # Apply PostgreSQL Phase 3 vulnerability intelligence schema migration
                schema_file_002 = DATA_DIR / "migrations" / "002_vulnerability_intelligence.sql"
                if schema_file_002.exists():
                    ddl_002 = schema_file_002.read_text(encoding="utf-8")
                    await conn.execute(ddl_002)

                # Apply PostgreSQL Phase 4 Attack Graph & Risk Engine schema migration
                schema_file_003 = DATA_DIR / "migrations" / "003_graph_risk_engine.sql"
                if schema_file_003.exists():
                    ddl_003 = schema_file_003.read_text(encoding="utf-8")
                    await conn.execute(ddl_003)

                # Apply PostgreSQL Phase 6 Scanner Foundation schema migration
                schema_file_004 = DATA_DIR / "migrations" / "004_scanner_foundation.sql"
                if schema_file_004.exists():
                    ddl_004 = schema_file_004.read_text(encoding="utf-8")
                    await conn.execute(ddl_004)

                # Apply PostgreSQL Phase 7 ProjectDiscovery httpx schema migration
                schema_file_005 = DATA_DIR / "migrations" / "005_httpx_service_intelligence.sql"
                if schema_file_005.exists():
                    ddl_005 = schema_file_005.read_text(encoding="utf-8")
                    await conn.execute(ddl_005)

                # Apply PostgreSQL Phase 8 OWASP ZAP Web Intelligence schema migration
                schema_file_006 = DATA_DIR / "migrations" / "006_zap_web_intelligence.sql"
                if schema_file_006.exists():
                    ddl_006 = schema_file_006.read_text(encoding="utf-8")
                    await conn.execute(ddl_006)

                # Apply PostgreSQL Phase 9 Aqua Security Trivy schema migration
                schema_file_007 = DATA_DIR / "migrations" / "007_trivy_supply_chain.sql"
                if schema_file_007.exists():
                    ddl_007 = schema_file_007.read_text(encoding="utf-8")
                    await conn.execute(ddl_007)

                # Apply PostgreSQL Phase 10 ProjectDiscovery Nuclei schema migration
                schema_file_008 = DATA_DIR / "migrations" / "008_nuclei_template_intelligence.sql"
                if schema_file_008.exists():
                    ddl_008 = schema_file_008.read_text(encoding="utf-8")
                    await conn.execute(ddl_008)

                # Apply PostgreSQL Phase 11 Unified Scan Orchestrator schema migration
                schema_file_009 = DATA_DIR / "migrations" / "009_scan_orchestrator_stages.sql"
                if schema_file_009.exists():
                    ddl_009 = schema_file_009.read_text(encoding="utf-8")
                    await conn.execute(ddl_009)

                # Apply PostgreSQL Phase 12 PDF Report schema migration
                schema_file_010 = DATA_DIR / "migrations" / "010_scan_reports.sql"
                if schema_file_010.exists():
                    ddl_010 = schema_file_010.read_text(encoding="utf-8")
                    await conn.execute(ddl_010)

                # Apply PostgreSQL Row Level Security (RLS) & PostgREST hardening migration
                schema_file_011 = DATA_DIR / "migrations" / "011_enable_supabase_rls.sql"
                if schema_file_011.exists():
                    ddl_011 = schema_file_011.read_text(encoding="utf-8")
                    await conn.execute(ddl_011)

                # Mark interrupted scans from prior runs as failed
                await conn.execute("""
                    UPDATE scans
                    SET status = 'failed',
                        error_message = 'Scan interrupted by system restart',
                        updated_at = NOW()
                    WHERE status IN ('pending', 'running');
                """)
            _postgres_active = True
            return
        except Exception as pg_err:
            logger.warning(
                f"PostgreSQL connection to {get_clean_pg_url(DATABASE_URL)} failed: {pg_err}. "
                "Automatically activating local SQLite fallback mode."
            )
            _postgres_active = False
            if pg_pool_manager:
                try:
                    await pg_pool_manager.close()
                except Exception:
                    pass

    # SQLite initialization
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    await db_queue.start()
    async with get_db() as db:
        # 1. Threat Indicators
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                confidence REAL DEFAULT 0.0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 2. Scans Lifecycle Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER DEFAULT 0,
                current_step TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                error_message TEXT,
                authorization_id TEXT,
                scope TEXT DEFAULT 'FULL_PASSIVE',
                requested_scanners TEXT DEFAULT '["passive"]',
                stage_results TEXT DEFAULT '{}',
                overall_risk_score REAL DEFAULT 0.0
            );
        """)

        # Add Phase 11 columns to scans table if migrating existing SQLite database
        for col_def in [
            "requested_scanners TEXT DEFAULT '[\"passive\"]'",
            "stage_results TEXT DEFAULT '{}'",
            "overall_risk_score REAL DEFAULT 0.0",
        ]:
            try:
                await db.execute(f"ALTER TABLE scans ADD COLUMN {col_def};")
            except Exception:
                pass

        # 3. Scan Findings Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL,
                ip TEXT NOT NULL,
                tech TEXT NOT NULL,
                status TEXT NOT NULL,
                risk TEXT NOT NULL,
                score TEXT NOT NULL,
                ports TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 4. Consent Domains
        await db.execute("""
            CREATE TABLE IF NOT EXISTS consent_domains (
                domain TEXT PRIMARY KEY,
                authorized_by TEXT DEFAULT 'security-admin',
                scope TEXT DEFAULT 'FULL_RECON',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 5. Authorizations
        await db.execute("""
            CREATE TABLE IF NOT EXISTS authorizations (
                id TEXT PRIMARY KEY,
                target_domain TEXT NOT NULL,
                permitted_scope TEXT NOT NULL DEFAULT 'FULL_PASSIVE',
                operator_id TEXT NOT NULL DEFAULT 'local-operator-dev',
                status TEXT NOT NULL DEFAULT 'pending',
                verification_method TEXT NOT NULL DEFAULT 'dns_txt',
                verification_token TEXT NOT NULL,
                challenge_record_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP,
                revocation_reason TEXT
            );
        """)

        # 6. Audit Events
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                authorization_id TEXT,
                scan_id TEXT,
                operator_id TEXT NOT NULL DEFAULT 'local-operator-dev',
                target TEXT NOT NULL,
                detail TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 7. Passive Observations
        await db.execute("""
            CREATE TABLE IF NOT EXISTS passive_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                authorization_id TEXT,
                asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                query_type TEXT NOT NULL,
                observed_value TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                raw_metadata TEXT DEFAULT '{}',
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 8. Vulnerability Corpus Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL DEFAULT 'NVD',
                title TEXT,
                description TEXT,
                published_at TIMESTAMP,
                last_modified_at TIMESTAMP,
                cvss_version TEXT,
                cvss_score REAL DEFAULT 0.0,
                cvss_severity TEXT DEFAULT 'UNKNOWN',
                cvss_vector TEXT,
                epss_score REAL,
                epss_percentile REAL,
                cwe_ids TEXT DEFAULT '[]',
                configurations TEXT DEFAULT '[]',
                references_json TEXT DEFAULT '[]',
                remediation_notes TEXT,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_weaponized INTEGER DEFAULT 0,
                metasploit_module TEXT,
                cisa_kev INTEGER DEFAULT 0
            );
        """)

        # Ensure Metasploit weaponization and CISA KEV columns exist on existing databases
        for col_name, col_def in [("is_weaponized", "INTEGER DEFAULT 0"), ("metasploit_module", "TEXT"), ("cisa_kev", "INTEGER DEFAULT 0")]:
            try:
                await db.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass

        # 9. Normalized Asset Fingerprints Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS asset_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                asset_id TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                version TEXT,
                version_scheme TEXT DEFAULT 'semver',
                cpe23 TEXT,
                os_metadata TEXT,
                service_metadata TEXT,
                fingerprint_source TEXT NOT NULL,
                is_inferred INTEGER DEFAULT 0,
                confidence REAL DEFAULT 1.0,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 10. Vulnerability Applicability Findings Table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                cve_id TEXT NOT NULL,
                fingerprint_id INTEGER,
                applicability_status TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                match_rationale TEXT NOT NULL,
                evaluated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 11. Vulnerability Sync Checkpoints
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerability_sync_checkpoints (
                source TEXT PRIMARY KEY,
                last_sync_timestamp TIMESTAMP,
                total_synced INTEGER DEFAULT 0,
                status TEXT DEFAULT 'idle',
                error_message TEXT
            );
        """)

        # 12. Graph Snapshots Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS graph_snapshots (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                snapshot_version INTEGER NOT NULL DEFAULT 1,
                schema_version TEXT NOT NULL DEFAULT '4.0',
                nodes_count INTEGER NOT NULL DEFAULT 0,
                edges_count INTEGER NOT NULL DEFAULT 0,
                graph_data TEXT NOT NULL,
                statistics TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 13. Attack Paths Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS attack_paths (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                source_node TEXT NOT NULL,
                target_node TEXT NOT NULL,
                path_nodes TEXT NOT NULL,
                path_edges TEXT NOT NULL,
                total_cost REAL NOT NULL,
                priority_score REAL NOT NULL,
                cves TEXT DEFAULT '[]',
                hypothetical_transitions_count INTEGER DEFAULT 0,
                confidence_level TEXT DEFAULT 'medium',
                preconditions TEXT DEFAULT '[]',
                recommendations TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (snapshot_id) REFERENCES graph_snapshots(id) ON DELETE CASCADE
            );
        """)

        # 14. Risk Assessments Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                snapshot_id TEXT,
                overall_risk_score REAL NOT NULL,
                criticality_score REAL NOT NULL,
                confirmed_vulns_count INTEGER DEFAULT 0,
                potential_vulns_count INTEGER DEFAULT 0,
                compromise_likelihood REAL NOT NULL,
                factors TEXT DEFAULT '{}',
                scoring_version TEXT DEFAULT '4.0-drishti-risk',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 15. Mitigation Simulations Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS mitigation_simulations (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                snapshot_id TEXT NOT NULL,
                scenario_name TEXT NOT NULL,
                mitigated_cves TEXT DEFAULT '[]',
                disabled_edges TEXT DEFAULT '[]',
                original_risk_score REAL NOT NULL,
                simulated_risk_score REAL NOT NULL,
                risk_delta REAL NOT NULL,
                broken_paths_count INTEGER DEFAULT 0,
                remaining_paths_count INTEGER DEFAULT 0,
                details TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 16. OWASP ZAP Web Alerts Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS zap_alert_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                plugin_id TEXT NOT NULL,
                alert_name TEXT NOT NULL,
                risk TEXT NOT NULL DEFAULT 'Informational',
                confidence TEXT NOT NULL DEFAULT 'Medium',
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 80,
                param TEXT DEFAULT '',
                attack TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                description TEXT DEFAULT '',
                solution TEXT DEFAULT '',
                reference TEXT DEFAULT '',
                cwe_id INTEGER,
                wasc_id INTEGER,
                source_scanner TEXT NOT NULL DEFAULT 'OWASP ZAP',
                verification_status TEXT NOT NULL DEFAULT 'unverified_finding',
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 17. Trivy Supply Chain Findings Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS trivy_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                target_resource TEXT NOT NULL,
                finding_class TEXT NOT NULL,
                vulnerability_id TEXT,
                rule_id TEXT,
                title TEXT,
                severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                package_name TEXT,
                installed_version TEXT,
                fixed_version TEXT,
                primary_url TEXT,
                description TEXT,
                remediation_guidance TEXT,
                evidence TEXT,
                line_number INTEGER,
                confidence TEXT DEFAULT 'HIGH',
                scanner_name TEXT NOT NULL DEFAULT 'Aqua Security Trivy',
                scanner_version TEXT,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 18. Nuclei Template Intelligence Findings Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS nuclei_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                template_id TEXT NOT NULL,
                template_name TEXT,
                severity TEXT NOT NULL DEFAULT 'info',
                matched_at TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER DEFAULT 80,
                scheme TEXT DEFAULT 'http',
                url TEXT,
                matcher_name TEXT,
                extracted_results TEXT,
                type TEXT DEFAULT 'http',
                description TEXT,
                remediation TEXT,
                reference TEXT,
                tags TEXT,
                cve_id TEXT,
                cwe_id TEXT,
                cvss_score REAL,
                curl_command TEXT,
                evidence TEXT,
                confidence TEXT DEFAULT 'TENTATIVE',
                scanner_name TEXT NOT NULL DEFAULT 'ProjectDiscovery Nuclei',
                scanner_version TEXT,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 19. Scan Stages Table (Phase 11 Unified Orchestration SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_stages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                scanner_name TEXT NOT NULL,
                stage_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                progress INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds REAL DEFAULT 0.0,
                findings_count INTEGER DEFAULT 0,
                error_message TEXT,
                stage_metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 20. Active Port Observations Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS active_port_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                host TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'tcp',
                state TEXT NOT NULL DEFAULT 'open',
                service_name TEXT,
                product TEXT,
                version TEXT,
                extra_info TEXT,
                cpe23 TEXT,
                scanner_name TEXT NOT NULL DEFAULT 'Nmap',
                scanner_version TEXT,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 21. HTTP Service Observations Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS http_service_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                url TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                scheme TEXT NOT NULL DEFAULT 'http',
                status_code INTEGER,
                title TEXT,
                webserver TEXT,
                content_type TEXT,
                content_length INTEGER,
                technologies TEXT DEFAULT '[]',
                final_url TEXT,
                ip TEXT,
                cname TEXT,
                response_time_ms REAL,
                scanner_name TEXT NOT NULL DEFAULT 'ProjectDiscovery httpx',
                scanner_version TEXT,
                observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # 22. Scan Reports Table (SQLite fallback)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL UNIQUE,
                file_path TEXT NOT NULL,
                file_size INTEGER DEFAULT 0,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                error_message TEXT,
                report_metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
        """)

        # Handle interrupted scans from prior process termination
        await db.execute("""
            UPDATE scans
            SET status = 'failed',
                error_message = 'Scan interrupted by system restart',
                updated_at = CURRENT_TIMESTAMP
            WHERE status IN ('pending', 'running');
        """)

        await db.commit()


# ---------------------------------------------------------------------------
# Operational Status & Diagnostics
# ---------------------------------------------------------------------------

async def get_db_status() -> Dict[str, Any]:
    """Returns real-time status and diagnostics of active database backend."""
    t0 = time.perf_counter()
    if is_postgres_enabled():
        try:
            pool = await pg_pool_manager.get_pool() if pg_pool_manager else None
            if not pool:
                return {
                    "engine": "postgresql",
                    "status": "error",
                    "message": "Pool uninitialized",
                }
            async with pool.acquire() as conn:
                version = await conn.fetchval("SELECT version();")
                t_latency = round((time.perf_counter() - t0) * 1000, 2)
                return {
                    "engine": "postgresql",
                    "status": "connected",
                    "supabase": True if "supabase" in DATABASE_URL.lower() else False,
                    "version": version[:50] if version else "PostgreSQL",
                    "pool": {
                        "min_size": pool.get_min_size(),
                        "max_size": pool.get_max_size(),
                        "size": pool.get_size(),
                        "idle": pool.get_idle_size(),
                    },
                    "latency_ms": t_latency,
                }
        except Exception as ex:
            return {
                "engine": "postgresql",
                "status": "disconnected",
                "error": str(ex),
                "fallback": "sqlite",
            }

    # SQLite status
    import aiosqlite
    try:
        async with get_db() as db:
            async with db.execute("PRAGMA journal_mode;") as cursor:
                row = await cursor.fetchone()
                wal = (row[0].lower() == "wal") if row else False
            t_latency = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "engine": "sqlite",
                "status": "operational",
                "wal_mode": wal,
                "path": str(DB_PATH.name),
                "latency_ms": t_latency,
            }
    except Exception as ex:
        return {
            "engine": "sqlite",
            "status": "error",
            "error": str(ex),
        }
