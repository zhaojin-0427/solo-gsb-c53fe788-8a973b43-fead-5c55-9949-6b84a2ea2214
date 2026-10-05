"""FastAPI surface for the damaged-ZIP recovery service."""

from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from .recover import RejectError, run_recovery
from .store import Store

MiB = 1024 * 1024
GiB = 1024 * MiB


@dataclass
class Settings:
    data_dir: str = "./data"
    max_upload_bytes: int = 256 * MiB
    max_expand_bytes: int = 1 * GiB

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            data_dir=os.environ.get("ZIPRECOVER_DATA_DIR", "./data"),
            max_upload_bytes=int(
                os.environ.get("ZIPRECOVER_MAX_UPLOAD_BYTES", 256 * MiB)
            ),
            max_expand_bytes=int(
                os.environ.get("ZIPRECOVER_MAX_EXPAND_BYTES", 1 * GiB)
            ),
        )


def create_app(settings: "Settings | None" = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app):
        # persistence is initialised at startup, not at import time
        os.makedirs(settings.data_dir, exist_ok=True)
        app.state.store = Store(settings.data_dir)
        yield

    app = FastAPI(
        title="Damaged ZIP Recovery API",
        version="1.0.0",
        summary="Recover STORED/DEFLATE members from ZIP archives with a "
        "missing or truncated central directory.",
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ------------------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return {
            "service": "damaged-zip-recovery",
            "endpoints": {
                "POST /recover": "upload a (damaged) ZIP, get a recovery report",
                "GET /recover": "list recovery jobs",
                "GET /recover/{id}": "fetch a recovery report",
                "GET /recover/{id}/entries/{n}": "download original bytes of entry n",
                "GET /healthz": "liveness probe",
            },
            "limits": {
                "max_upload_bytes": settings.max_upload_bytes,
                "max_expand_bytes": settings.max_expand_bytes,
            },
        }

    # ------------------------------------------------------------------
    @app.post("/recover", status_code=201)
    async def recover(
        request: Request,
        filename: "str | None" = Query(
            default=None, description="optional original archive name"
        ),
    ):
        settings = request.app.state.settings
        store: Store = request.app.state.store

        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                clen = int(cl)
            except ValueError:
                clen = None
            if clen is not None and clen > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail={
                        "error": "upload_too_large",
                        "message": "upload exceeds the limit of "
                        f"{settings.max_upload_bytes} bytes",
                        "limit": settings.max_upload_bytes,
                    },
                )

        workdir = store.new_workdir()
        upload = os.path.join(workdir, "upload.bin")
        size = 0
        sha = hashlib.sha256()
        try:
            with open(upload, "wb") as f:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail={
                                "error": "upload_too_large",
                                "message": "upload exceeds the limit of "
                                f"{settings.max_upload_bytes} bytes",
                                "limit": settings.max_upload_bytes,
                            },
                        )
                    sha.update(chunk)
                    f.write(chunk)
            try:
                report = await run_in_threadpool(
                    run_recovery, upload, workdir, settings.max_expand_bytes
                )
            except RejectError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={"error": exc.code, "message": exc.message},
                )
            job_id = store.create_job(
                report,
                workdir,
                filename=filename,
                size=size,
                sha256=sha.hexdigest(),
                limits={
                    "max_upload_bytes": settings.max_upload_bytes,
                    "max_expand_bytes": settings.max_expand_bytes,
                },
            )
            return store.get_job(job_id)
        finally:
            # rejections and failures leave nothing behind
            store.drop_workdir(workdir)

    # ------------------------------------------------------------------
    @app.get("/recover")
    def list_jobs(request: Request):
        store: Store = request.app.state.store
        return {"jobs": store.list_jobs()}

    @app.get("/recover/{job_id}")
    def get_job(job_id: str, request: Request):
        store: Store = request.app.state.store
        report = store.get_job(job_id)
        if report is None:
            raise HTTPException(
                status_code=404,
                detail={"error": "not_found",
                        "message": f"no recovery job {job_id!r}"},
            )
        return report

    @app.get("/recover/{job_id}/entries/{n}")
    def get_entry(job_id: str, n: int, request: Request):
        store: Store = request.app.state.store
        entry = store.get_entry(job_id, n)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "not_found",
                    "message": f"no entry {n} in recovery job {job_id!r}",
                },
            )
        return FileResponse(
            entry["path"],
            media_type="application/octet-stream",
            filename=entry["name"],
            headers={
                "X-Entry-Name": quote(entry["name"]),
                "X-Entry-Name-Seq": str(entry["name_seq"]),
                "X-Entry-Status": entry["status"],
                "X-Entry-SHA256": entry["sha256"],
            },
        )

    return app


app = create_app()
