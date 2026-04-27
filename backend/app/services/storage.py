import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "scanner.db"


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            entry       TEXT    NOT NULL UNIQUE,
            entry_type  TEXT    NOT NULL DEFAULT 'domain',
            reason      TEXT    DEFAULT '',
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            entry       TEXT    NOT NULL UNIQUE,
            entry_type  TEXT    NOT NULL DEFAULT 'domain',
            created_at  TEXT    DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            from_addr       TEXT,
            subject         TEXT,
            classification  TEXT,
            confidence      REAL,
            rules_score     INTEGER,
            rule_hits       TEXT,
            scanned_at      TEXT    DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()


# ── Blocklist ────────────────────────────────────────────

def add_blocklist(entry: str, entry_type: str = "domain", reason: str = ""):
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO blocklist (entry, entry_type, reason) VALUES (?, ?, ?)",
            (entry.lower().strip(), entry_type, reason),
        )
        conn.commit()
    finally:
        conn.close()


def remove_blocklist(entry_id: int):
    conn = _conn()
    try:
        conn.execute("DELETE FROM blocklist WHERE id = ?", (entry_id,))
        conn.commit()
    finally:
        conn.close()


def get_blocklist() -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM blocklist ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def is_blocked(value: str) -> bool:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM blocklist WHERE entry = ? LIMIT 1",
            (value.lower().strip(),),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ── Whitelist ────────────────────────────────────────────

def add_whitelist(entry: str, entry_type: str = "domain"):
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO whitelist (entry, entry_type) VALUES (?, ?)",
            (entry.lower().strip(), entry_type),
        )
        conn.commit()
    finally:
        conn.close()


def remove_whitelist(entry_id: int):
    conn = _conn()
    try:
        conn.execute("DELETE FROM whitelist WHERE id = ?", (entry_id,))
        conn.commit()
    finally:
        conn.close()


def get_whitelist() -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM whitelist ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def is_whitelisted(value: str) -> bool:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM whitelist WHERE entry = ? LIMIT 1",
            (value.lower().strip(),),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ── Scan History ─────────────────────────────────────────

def save_scan(from_addr: str, subject: str, classification: str,
              confidence: float, rules_score: int, rule_hits: list[dict]):
    conn = _conn()
    try:
        conn.execute(
            """INSERT INTO scan_history
               (from_addr, subject, classification, confidence, rules_score, rule_hits)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (from_addr, subject, classification, confidence, rules_score, json.dumps(rule_hits)),
        )
        conn.commit()
    finally:
        conn.close()


def get_history(limit: int = 50) -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["rule_hits"] = json.loads(d["rule_hits"]) if d["rule_hits"] else []
            result.append(d)
        return result
    finally:
        conn.close()


def get_history_stats() -> dict:
    conn = _conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        phishing = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE classification = 'Phishing'"
        ).fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE classification = 'Suspicious'"
        ).fetchone()[0]
        safe = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE classification = 'Safe'"
        ).fetchone()[0]

        top_offenders = conn.execute("""
            SELECT from_addr, COUNT(*) as cnt
            FROM scan_history
            WHERE classification IN ('Phishing', 'Suspicious')
            GROUP BY from_addr
            ORDER BY cnt DESC
            LIMIT 5
        """).fetchall()

        return {
            "total_scans": total,
            "phishing": phishing,
            "suspicious": suspicious,
            "safe": safe,
            "top_flagged_senders": [{"from_addr": r[0], "count": r[1]} for r in top_offenders],
        }
    finally:
        conn.close()


def sender_flag_count(from_addr: str) -> int:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE from_addr = ? AND classification IN ('Phishing', 'Suspicious')",
            (from_addr,),
        ).fetchone()
        return row[0] if row else 0
    finally:
        conn.close()
