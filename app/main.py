"""FastAPI surface for the damaged-ZIP recovery service."""
import gc
import hashlib
import mmap
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from starlette.concurrency import run_in_threadpool

from . import config, db, recovery


@asynccontextmanager
async def _lifespan(app):
    db.init()
    yield


app = FastAPI(
    title="Damaged ZIP Recovery API",
    version="1.0.0",
    description="Recovers STORED/DEFLATE entries from ZIP archives whose "
                "central directory is missing, truncated or damaged.",
    lifespan=_lifespan,
)


@app.get("/")
def root():
    return {
        "service": "damaged-zip-recovery",
        "endpoints": {
            "POST /recover": "upload a (possibly damaged) ZIP archive",
            "GET /recover/{id}": "fetch a previous recovery report",
            "GET /recover/{id}/entries/{n}": "download recovered entry bytes",
        },
        "limits": {
            "max_upload_bytes": config.MAX_UPLOAD_BYTES,
            "max_expanded_bytes": config.MAX_EXPANDED_BYTES,
        },
    }


def _empty_report() -> dict:
    return {
        "entries": [], "damaged_regions": [], "ambiguities": [],
        "central_directory": {"found": False, "offset": None,
                              "entries": None, "consistent": False,
                              "notes": ["empty input"]},
        "eocd_found": False, "truncated": True,
        "entry_count": 0, "certain_count": 0, "candidate_count": 0,
        "expanded_bytes": 0,
    }


def _drop_traceback_frames(exc: BaseException, _seen=None) -> None:
    """Clear frames held by an exception traceback.

    Frames of the parser hold memoryview slices over the archive mmap; the
    mmap cannot be closed while they are alive.  The frames have already
    unwound, so clearing them is safe.
    """
    if _seen is None:
        _seen = set()
    if id(exc) in _seen:
        return
    _seen.add(id(exc))
    tb = exc.__traceback__
    while tb is not None:
        try:
            tb.tb_frame.clear()
        except RuntimeError:
            pass
        tb = tb.tb_next
    for nxt in (exc.__cause__, exc.__context__):
        if nxt is not None:
            _drop_traceback_frames(nxt, _seen)


def _process(tmp_path: str, archive_id: str, filename: str, size: int,
             sha256: str) -> dict:
    """Blocking recovery work; runs in a thread pool."""
    entry_dir = os.path.join(config.entries_root(), archive_id)
    os.makedirs(entry_dir, exist_ok=True)
    try:
        if size == 0:
            report = _empty_report()
        else:
            with open(tmp_path, "rb") as f:
                mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                view = None
                try:
                    view = memoryview(mm)
                    try:
                        report = recovery.recover_archive(
                            mm, view, size, entry_dir,
                            config.MAX_EXPANDED_BYTES)
                    except BaseException as e:
                        _drop_traceback_frames(e)
                        raise
                finally:
                    if view is not None:
                        try:
                            view.release()
                        except Exception:
                            pass
                    try:
                        mm.close()
                    except BufferError:
                        gc.collect()
                        try:
                            mm.close()
                        except BufferError:
                            pass  # fd is reclaimed on process exit
    except Exception:
        # Rejections and unexpected errors alike: leave no partial results.
        shutil.rmtree(entry_dir, ignore_errors=True)
        raise

    report.update({
        "id": archive_id,
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "limits": {
            "max_upload_bytes": config.MAX_UPLOAD_BYTES,
            "max_expanded_bytes": config.MAX_EXPANDED_BYTES,
        },
    })
    for e in report["entries"]:
        e["download"] = f"/recover/{archive_id}/entries/{e['index']}"
    db.insert_archive(report)
    return report


@app.post("/recover", status_code=200)
async def post_recover(request: Request, filename: str | None = None):
    """Stream a ZIP archive to disk and recover its entries."""
    cl = request.headers.get("content-length")
    if cl is not None and cl.isdigit() and int(cl) > config.MAX_UPLOAD_BYTES:
        raise HTTPException(
            413, f"upload exceeds the limit of {config.MAX_UPLOAD_BYTES} bytes")

    archive_id = uuid.uuid4().hex
    tmp_path = os.path.join(config.uploads_dir(), archive_id + ".part")
    sha = hashlib.sha256()
    size = 0
    try:
        with open(tmp_path, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        413, f"upload exceeds the limit of "
                             f"{config.MAX_UPLOAD_BYTES} bytes")
                sha.update(chunk)
                f.write(chunk)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    if filename is None:
        filename = request.headers.get("x-filename") or "upload.zip"

    try:
        report = await run_in_threadpool(
            _process, tmp_path, archive_id, filename, size, sha.hexdigest())
    except recovery.Reject as r:
        raise HTTPException(r.status, r.detail)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return report


@app.get("/recover/{archive_id}")
def get_recover(archive_id: str):
    report = db.get_archive(archive_id)
    if report is None:
        raise HTTPException(404, "archive not found")
    return report


@app.get("/recover/{archive_id}/entries/{n}")
def get_entry(archive_id: str, n: int):
    row = db.get_entry(archive_id, n)
    if row is None:
        raise HTTPException(404, "entry not found")
    path = os.path.join(config.entries_root(), row["data_path"])
    if not os.path.isfile(path):
        raise HTTPException(404, "entry data missing")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=row["name"],
        headers={
            "X-Entry-Name-Seq": str(row["name_seq"]),
            "X-Entry-SHA256": row["sha256"],
        },
    )
