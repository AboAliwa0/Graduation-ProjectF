import sqlite3
import os

# -----------------------
# 🔗 Connect DB
# -----------------------

def connect():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(BASE_DIR, "scanner.db")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # 🔥 مهم جدًا

    return conn


# -----------------------
# 🏗️ Init DB
# -----------------------

def init_db():
    conn = connect()
    cursor = conn.cursor()

    # -----------------------
    # 👤 Users
    # -----------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    # -----------------------
    # 🧠 Scans (Updated)
    # -----------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,

        result TEXT,                -- JSON string
        status TEXT DEFAULT 'done', -- running / done
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()


# -----------------------
# 💾 Save Scan
# -----------------------

def save_scan(user_id, target, result_json):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (user_id, target, result)
        VALUES (?, ?, ?)
    """, (user_id, target, result_json))

    conn.commit()
    conn.close()


# -----------------------
# 📊 Get History
# -----------------------

def get_user_scans(user_id):
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM scans
        WHERE user_id=?
        ORDER BY id DESC
    """, (user_id,))

    rows = cursor.fetchall()
    conn.close()

    return rows