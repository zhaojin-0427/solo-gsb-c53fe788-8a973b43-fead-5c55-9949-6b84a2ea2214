"""SQLite persistence for recovery reports and entry metadata."""
import json
import os
import sqlite3

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS archives(
  id          TEXT PRIMARY KEY,
  filename    TEXT NOT NULL,
  size        INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  report      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries(
  archive_id        TEXT NOT NULL,
  idx               INTEGER NOT NULL,
  name              TEXT NOT NULL,
  name_seq          INTEGER NOT NULL,
  sha256            TEXT NOT NULL,
  uncompressed_size INTEGER NOT NULL,
  data_path         TEXT NOT NULL,
  PRIMARY KEY(archive_id, idx)
);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init() -> None:
    os.makedirs(config.DATA_DIR, exist_ok=True)
    os.makedirs(config.entries_root(), exist_ok=True)
    os.makedirs(config.uploads_dir(), exist_ok=True)
    with _conn() as c:
        c.executescript(_SCHEMA)


def insert_archive(report: dict) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO archives(id, filename, size, sha256, created_at,"
            " report) VALUES(?,?,?,?,?,?)",
            (report["id"], report["filename"], report["size"],
             report["sha256"], report["created_at"], json.dumps(report)),
        )
        for e in report["entries"]:
            c.execute(
                "INSERT INTO entries(archive_id, idx, name, name_seq,"
                " sha256, uncompressed_size, data_path)"
                " VALUES(?,?,?,?,?,?,?)",
                (report["id"], e["index"], e["name"], e["name_seq"],
                 e["sha256"], e["uncompressed_size"],
                 f"{report['id']}/{e['index']}.bin"),
            )


def get_archive(archive_id: str):
    with _conn() as c:
        row = c.execute("SELECT report FROM archives WHERE id = ?",
                        (archive_id,)).fetchone()
    return json.loads(row["report"]) if row else None


def get_entry(archive_id: str, idx: int):
    with _conn() as c:
        row = c.execute(
            "SELECT name, name_seq, sha256, uncompressed_size, data_path"
            " FROM entries WHERE archive_id = ? AND idx = ?",
            (archive_id, idx)).fetchone()
    return dict(row) if row else None
