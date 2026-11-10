"""Database storage module using SQLite3.

Stores scan metadata, timestamps, submitted URL, final score, risk band, fetch status,
and JSON-serialized evidence flags.
"""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create and configure a SQLite connection."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize database tables if they do not exist."""
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL UNIQUE,
                scanned_at TEXT NOT NULL,
                submitted_url TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,
                fetch_status TEXT NOT NULL,
                signals_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanned_at ON scans (scanned_at DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_id ON scans (scan_id);")
        conn.commit()


def save_scan(
    scan_id: str,
    scanned_at: str,
    submitted_url: str,
    score: int,
    risk_band: str,
    fetch_status: str,
    signals: list[dict[str, Any]],
    limitations: list[str],
    db_path: str = DEFAULT_DB_PATH,
) -> int:
    """Insert a new scan record into the database."""
    init_db(db_path)
    signals_json = json.dumps(signals)
    limitations_json = json.dumps(limitations)

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                scan_id, scanned_at, submitted_url, score, risk_band, fetch_status, signals_json, limitations_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (scan_id, scanned_at, submitted_url, score, risk_band, fetch_status, signals_json, limitations_json),
        )
        conn.commit()
        return cursor.lastrowid or 0


def get_recent_scans(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    """Retrieve recent scans ordered by scan date descending."""
    init_db(db_path)
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, scan_id, scanned_at, submitted_url, score, risk_band, fetch_status, signals_json, limitations_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        results: list[dict[str, Any]] = []
        for r in rows:
            try:
                signals = json.loads(r["signals_json"])
            except Exception:
                signals = []
            try:
                limitations = json.loads(r["limitations_json"])
            except Exception:
                limitations = []

            results.append(
                {
                    "id": r["id"],
                    "scan_id": r["scan_id"],
                    "scanned_at": r["scanned_at"],
                    "submitted_url": r["submitted_url"],
                    "score": r["score"],
                    "risk_band": r["risk_band"],
                    "fetch_status": r["fetch_status"],
                    "signals": signals,
                    "signal_count": len(signals),
                    "limitations": limitations,
                }
            )
        return results
