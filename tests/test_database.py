import importlib
import sqlite3


def test_v3_database_is_migrated_and_active_jobs_are_recovered(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'done',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO users (email,password) VALUES ('legacy@example.com','hash');
        INSERT INTO scans (user_id,target,result,status) VALUES (1,'https://example.com','[]','running');
        """
    )
    conn.commit(); conn.close()

    monkeypatch.setenv("DATABASE_PATH", str(path))
    import database

    database = importlib.reload(database)
    database.init_db()
    conn = database.connect()
    user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    scan_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    scan = conn.execute("SELECT status,error_message,completed_at FROM scans WHERE id=1").fetchone()
    conn.close()

    assert {"role", "is_active", "last_login_at"}.issubset(user_columns)
    assert {"progress", "request_budget", "risk_score", "selected_scanners", "tool_version"}.issubset(scan_columns)
    assert scan["status"] == "interrupted"
    assert scan["completed_at"]
    assert "restarted" in scan["error_message"]


def test_redis_backend_preserves_queued_jobs_for_worker_recovery(tmp_path, monkeypatch):
    path = tmp_path / "redis.db"
    monkeypatch.setenv("DATABASE_PATH", str(path))
    monkeypatch.setenv("SCAN_QUEUE_BACKEND", "redis")
    import database

    database = importlib.reload(database)
    database.init_db()
    conn = database.connect()
    conn.execute("INSERT INTO users (email,password) VALUES (?,?)", ("redis@example.com", "hash"))
    conn.execute(
        "INSERT INTO scans (user_id,target,result,status) VALUES (?,?,?,?)",
        (1, "https://example.com", "[]", "queued"),
    )
    conn.commit(); conn.close()

    database.init_db()
    conn = database.connect()
    row = conn.execute("SELECT status FROM scans WHERE id=1").fetchone()
    conn.close()
    assert row["status"] == "queued"
