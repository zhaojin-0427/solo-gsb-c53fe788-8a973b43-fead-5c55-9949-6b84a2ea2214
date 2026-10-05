"""Persistence: recovered-entry payloads on disk, metadata in SQLite."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    filename    TEXT,
    size        INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    report      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    job_id   TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    n        INTEGER NOT NULL,
    name     TEXT NOT NULL,
    name_seq INTEGER NOT NULL,
    status   TEXT NOT NULL,
    size     INTEGER NOT NULL,
    sha256   TEXT NOT NULL,
    payload  TEXT NOT NULL,
    PRIMARY KEY (job_id, n)
);
"""


class Store:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.jobs_dir = os.path.join(data_dir, "jobs")
        self.tmp_dir = os.path.join(data_dir, "tmp")
        os.makedirs(self.jobs_dir, exist_ok=True)
        os.makedirs(self.tmp_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            os.path.join(data_dir, "recover.db"), check_same_thread=False
        )
        self._db.executescript(SCHEMA)
        self._db.commit()

    # ------------------------------------------------------------------
    def new_workdir(self) -> str:
        """Fresh scratch directory for one recovery attempt."""
        import tempfile

        return tempfile.mkdtemp(prefix="job-", dir=self.tmp_dir)

    @staticmethod
    def drop_workdir(path: str) -> None:
        shutil.rmtree(path, ignore_errors=True)

    # ------------------------------------------------------------------
    def create_job(self, report: dict, workdir: str, *, filename,
                   size: int, sha256: str, limits: dict) -> str:
        """Atomically persist a finished recovery (payloads + metadata)."""
        job_id = uuid.uuid4().hex
        created = datetime.now(timezone.utc).isoformat()
        for e in report["entries"]:
            e["download"] = f"/recover/{job_id}/entries/{e['n']}"
        full = {
            "id": job_id,
            "status": "ok",
            "created_at": created,
            "upload": {"filename": filename, "size": size, "sha256": sha256},
            "limits": limits,
        }
        full.update(report)

        job_dir = os.path.join(self.jobs_dir, job_id)
        os.makedirs(job_dir)
        src = os.path.join(workdir, "entries")
        dst = os.path.join(job_dir, "entries")
        if os.path.isdir(src):
            shutil.move(src, dst)
        else:
            os.makedirs(dst)

        with self._lock:
            self._db.execute(
                "INSERT INTO jobs (id, created_at, filename, size, sha256,"
                " report) VALUES (?,?,?,?,?,?)",
                (job_id, created, filename, size, sha256, json.dumps(full)),
            )
            for e in report["entries"]:
                self._db.execute(
                    "INSERT INTO entries (job_id, n, name, name_seq,"
                    " status, size, sha256, payload) VALUES (?,?,?,?,?,?,?,?)",
                    (job_id, e["n"], e["name"], e["name_seq"], e["status"],
                     e["size"], e["sha256"], f"entries/{e['n']}.bin"),
                )
            self._db.commit()
        return job_id

    # ------------------------------------------------------------------
    def get_job(self, job_id: str) -> Optional[dict]:
        row = self._db.execute(
            "SELECT report FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_jobs(self) -> list:
        rows = self._db.execute(
            "SELECT id, created_at, filename, size, sha256, report"
            " FROM jobs ORDER BY created_at"
        ).fetchall()
        out = []
        for job_id, created, filename, size, sha256, report in rows:
            rep = json.loads(report)
            out.append(
                {
                    "id": job_id,
                    "created_at": created,
                    "filename": filename,
                    "size": size,
                    "sha256": sha256,
                    "summary": rep["summary"],
                }
            )
        return out

    def get_entry(self, job_id: str, n: int) -> Optional[dict]:
        row = self._db.execute(
            "SELECT name, name_seq, status, size, sha256, payload"
            " FROM entries WHERE job_id = ? AND n = ?",
            (job_id, n),
        ).fetchone()
        if not row:
            return None
        name, name_seq, status, size, sha256, payload = row
        path = os.path.join(self.jobs_dir, job_id, payload)
        if not os.path.isfile(path):
            return None
        return {
            "name": name,
            "name_seq": name_seq,
            "status": status,
            "size": size,
            "sha256": sha256,
            "path": path,
        }
