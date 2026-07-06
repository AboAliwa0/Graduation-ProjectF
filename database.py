from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
SERVERLESS_TMP_DIR = Path("/tmp")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _running_on_vercel() -> bool:
    return bool(os.environ.get("VERCEL"))


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def database_path() -> Path:
    configured = os.getenv("DATABASE_PATH", "data/scanner.db").strip() or "data/scanner.db"
    path = Path(configured)
    if _running_on_vercel():
        if not path.is_absolute() or not _is_within(path, SERVERLESS_TMP_DIR):
            path = SERVERLESS_TMP_DIR / "cyberscan" / path.name
    elif not path.is_absolute():
        path = BASE_DIR / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def connect() -> sqlite3.Connection:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if _running_on_vercel():
        conn.execute("PRAGMA journal_mode = DELETE")
    else:
        conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_missing_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = _table_columns(conn, table)
    for name, declaration in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")


def init_db() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'developer',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_login_at TEXT
        );

        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL DEFAULT '[]',
            artifacts TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'queued',
            selected_scanners TEXT NOT NULL DEFAULT '[]',
            scan_mode TEXT NOT NULL DEFAULT 'standard',
            progress INTEGER NOT NULL DEFAULT 0,
            current_scanner TEXT NOT NULL DEFAULT '',
            request_count INTEGER NOT NULL DEFAULT 0,
            request_budget INTEGER NOT NULL DEFAULT 120,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            risk_score REAL NOT NULL DEFAULT 0,
            error_message TEXT NOT NULL DEFAULT '',
            tool_version TEXT NOT NULL DEFAULT '5.0.0',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TEXT,
            completed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT '',
            target_id TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL DEFAULT '{}',
            ip_address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS target_scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            hostname_pattern TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            include_subdomains INTEGER NOT NULL DEFAULT 0,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, hostname_pattern),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
        CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_logs(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scopes_user_active ON target_scopes(user_id, is_active);
        """
    )

    # Idempotent migration path for v3 databases.
    _add_missing_columns(
        conn,
        "users",
        {
            "role": "TEXT NOT NULL DEFAULT 'developer'",
            "is_active": "INTEGER NOT NULL DEFAULT 1",
            "last_login_at": "TEXT",
        },
    )

    # v3 used "analyst" as the role default. The application now has two
    # explicit account types; existing scanner users map to developers.
    conn.execute(
        "UPDATE users SET role='developer' WHERE role IS NULL OR role NOT IN ('student','developer')"
    )
    _add_missing_columns(
        conn,
        "scans",
        {
            "artifacts": "TEXT NOT NULL DEFAULT '{}'",
            "selected_scanners": "TEXT NOT NULL DEFAULT '[]'",
            "scan_mode": "TEXT NOT NULL DEFAULT 'standard'",
            "progress": "INTEGER NOT NULL DEFAULT 0",
            "current_scanner": "TEXT NOT NULL DEFAULT ''",
            "request_count": "INTEGER NOT NULL DEFAULT 0",
            "request_budget": "INTEGER NOT NULL DEFAULT 120",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
            "risk_score": "REAL NOT NULL DEFAULT 0",
            "error_message": "TEXT NOT NULL DEFAULT ''",
            "tool_version": "TEXT NOT NULL DEFAULT '5.0.0'",
            "started_at": "TEXT",
            "completed_at": "TEXT",
        },
    )

    # Local in-process jobs cannot survive a restart. Redis-backed jobs are
    # recovered by the reliable queue worker, so their state must be preserved.
    if os.getenv("SCAN_QUEUE_BACKEND", "local").strip().lower() != "redis":
        conn.execute(
            """
            UPDATE scans
            SET status='interrupted', completed_at=?, current_scanner='',
                error_message=CASE WHEN error_message='' THEN 'Application restarted while the scan was active.' ELSE error_message END
            WHERE status IN ('queued', 'running', 'cancelling')
            """,
            (utc_now(),),
        )
    conn.commit()
    conn.close()


def audit(
    action: str,
    *,
    user_id: int | None = None,
    target_type: str = "",
    target_id: str | int = "",
    details: dict[str, Any] | None = None,
    ip_address: str = "",
) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO audit_logs (user_id,action,target_type,target_id,details,ip_address,created_at) VALUES (?,?,?,?,?,?,?)",
        (
            user_id,
            action[:100],
            target_type[:80],
            str(target_id)[:120],
            json.dumps(details or {}, ensure_ascii=False)[:12000],
            ip_address[:128],
            utc_now(),
        ),
    )
    conn.commit()
    conn.close()


def save_scan(user_id: int, target: str, result_json: str) -> None:
    conn = connect()
    conn.execute(
        "INSERT INTO scans (user_id,target,result,status,progress,completed_at) VALUES (?,?,?,?,?,?)",
        (user_id, target, result_json, "done", 100, utc_now()),
    )
    conn.commit()
    conn.close()


def get_user_scans(user_id: int):
    conn = connect()
    rows = conn.execute("SELECT * FROM scans WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    conn.close()
    return rows
