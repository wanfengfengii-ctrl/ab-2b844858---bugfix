"""FastAPI application: resumable, idempotent cryo-EM upload sealing desk."""

from __future__ import annotations

import os
import re
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .storage import (
    CHUNK_SIZE,
    ConflictError,
    RejectError,
    UploadStore,
)

SESSION_RE = re.compile(r"^[A-Za-z0-9]{1,32}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATIC_DIR = os.environ.get("STATIC_DIR", "/app/frontend/dist")

app = FastAPI(title="Cryo-EM Sealing Desk", version="1.0.0")
store = UploadStore(DATA_DIR)


def _check_session(session: str) -> None:
    if not SESSION_RE.match(session):
        raise HTTPException(
            status_code=400,
            detail="session id must be 1-32 ASCII letters or digits",
        )


def _parse_int(name: str, raw: Optional[str]) -> Optional[int]:
    if raw is None or raw == "":
        return None
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"{name} must be an integer")
    # Reject non-canonical forms like "01", "1.0", "+1", " 1 ".
    if str(value) != raw:
        raise HTTPException(status_code=400, detail=f"{name} must be a canonical integer")
    return value


@app.exception_handler(RejectError)
def _reject_handler(_request: Request, exc: RejectError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(ConflictError)
def _conflict_handler(_request: Request, exc: ConflictError) -> JSONResponse:
    content: dict = {"error": str(exc)}
    if exc.reason is not None:
        content["reason"] = exc.reason
    return JSONResponse(status_code=409, content=content)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/uploads/{session}")
def get_status(session: str) -> dict:
    _check_session(session)
    status = store.status(session)
    if status is None:
        raise HTTPException(status_code=404, detail="no such session")
    return status


@app.put("/api/uploads/{session}/chunks")
async def put_chunk(
    session: str,
    request: Request,
    x_chunk_offset: Optional[str] = Header(default=None, alias="X-Chunk-Offset"),
    x_total_size: Optional[str] = Header(default=None, alias="X-Total-Size"),
    x_content_sha256: Optional[str] = Header(default=None, alias="X-Content-SHA256"),
) -> dict:
    _check_session(session)

    offset = _parse_int("X-Chunk-Offset", x_chunk_offset)
    if offset is None:
        raise HTTPException(status_code=400, detail="X-Chunk-Offset header is required")
    total_size = _parse_int("X-Total-Size", x_total_size)
    sha256 = x_content_sha256.lower() if x_content_sha256 else None
    if sha256 is not None and not SHA256_RE.match(sha256):
        raise HTTPException(
            status_code=400,
            detail="X-Content-SHA256 must be 64 lowercase hex characters",
        )

    data = await request.body()
    return store.put_chunk(session, offset, data, total_size, sha256)


@app.post("/api/uploads/{session}/seal")
def seal(session: str) -> JSONResponse:
    _check_session(session)
    try:
        result, _ok, missing = store.seal(session)
    except RejectError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except ConflictError as exc:
        # Digest mismatch: no receipt is produced.
        return JSONResponse(status_code=409, content={"error": str(exc)})

    if missing is not None:
        return JSONResponse(
            status_code=409,
            content={
                "error": "upload is incomplete",
                "missing_ranges": missing,
            },
        )
    return JSONResponse(status_code=200, content=result)


@app.post("/api/uploads/{session}/audit")
def audit(session: str) -> JSONResponse:
    """Re-verify that the bytes named by the receipt are still readable.

    Sealed sessions only. The check never mutates upload progress; for a
    healthy legacy session it merely backfills the trusted block index.
    """
    _check_session(session)
    try:
        result = store.audit(session)
    except RejectError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except ConflictError as exc:
        return JSONResponse(
            status_code=409,
            content={"error": str(exc), "reason": exc.reason or "conflict"},
        )
    if result is None:
        raise HTTPException(status_code=404, detail="no such session")
    return JSONResponse(status_code=200, content=result)


@app.post("/api/uploads/{session}/repair")
async def repair(session: str, request: Request) -> JSONResponse:
    """Restore abnormal chunks from the complete original file.

    Acceptance gate: the uploaded file must match BOTH the receipt length
    and its whole-file SHA-256 before any sealed byte is changed. Once
    validated it is staged persistently, so an interrupted replacement
    (or a service restart) resumes and converges. The receipt (including
    sealed_at) is never modified.
    """
    _check_session(session)
    data = await request.body()
    if not data:
        raise HTTPException(
            status_code=400,
            detail="request body must be the complete original file",
        )
    try:
        result = store.repair(session, data)
    except RejectError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except ConflictError as exc:
        return JSONResponse(
            status_code=409,
            content={"error": str(exc), "reason": exc.reason or "conflict"},
        )
    if result is None:
        raise HTTPException(status_code=404, detail="no such session")
    return JSONResponse(status_code=200, content=result)


# Serve the built React SPA from the same origin (API routes take priority).
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
