"""FastAPI server for NEXA-HexForge Local Console.

Provides a local-only HTTP API and static file serving for the web GUI.
All forensic operations are delegated to the existing hexforge modules.
"""
from __future__ import annotations

import os
import secrets
import hashlib
import re
import ipaddress
import signal
import tempfile
import threading
import webbrowser
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
import aiofiles

from hexforge.core import inspect_file, write_report
from hexforge.hexview import hex_rows
from hexforge.pe import inspect_pe
from hexforge.imports import inspect_imports
from hexforge.strings import extract_strings
from hexforge.indicators import section_indicators
from hexforge.artifacts import load_export, timeline as artifacts_timeline
from hexforge.timeline import correlate
from hexforge.custody import (
    register_evidence,
    append_event,
    verify_chain,
    verify_evidence,
    save_new,
    load_record,
)
from hexforge.registry_monitor import analyze_export
from hexforge.academy import hex_to_binary, binary_to_hex
from hexforge.byte_academy import inspect_byte
from hexforge.entropy_academy import inspect_section_entropy
from hexforge.import_academy import explain_imports
from hexforge.rva_academy import inspect_rva
from hexforge.pe_academy import explain_pe
from hexforge.file_utils import secure_open_file, validate_file_path


# ─── Server state ───
_server_thread: threading.Thread | None = None
_server_instance: Any = None
_shutdown_event = threading.Event()


# ─── Configuration ───
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MiB
MAX_CSV_SIZE = 32 * 1024 * 1024  # 32 MiB
MAX_JSON_SIZE = 8 * 1024 * 1024  # 8 MiB
UPLOAD_DIR = Path(tempfile.mkdtemp(prefix="nexa_hexforge_"))
REPORT_DIR = UPLOAD_DIR / "reports"
REPORT_DIR.mkdir(mode=0o700)
SESSION_TOKEN = secrets.token_urlsafe(32)
ACTIVE_PORT = DEFAULT_PORT


# ─── Pydantic models for request/response ───
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    modules: list[str] = [
        "core",
        "pe",
        "imports",
        "strings",
        "indicators",
        "hexview",
        "artifacts",
        "timeline",
        "custody",
        "registry_monitor",
        "academy",
    ]


class FileUploadResponse(BaseModel):
    file_id: str
    filename: str
    size: int
    sha256: str


class InspectRequest(BaseModel):
    file_id: str
    preview_bytes: int = Field(default=256, ge=0, le=4096)
    report_mode: str = Field(default="forense", pattern="^(forense|shareable|redacted)$")


class HexViewRequest(BaseModel):
    file_id: str
    offset: int = Field(ge=0)
    length: int = Field(default=256, ge=0, le=65536)
    width: int = Field(default=16, ge=8, le=32)

    @field_validator("width")
    @classmethod
    def validate_width(cls, v: int) -> int:
        if v not in (8, 16, 32):
            raise ValueError("Width must be 8, 16, or 32")
        return v


class StringsRequest(BaseModel):
    file_id: str
    min_length: int = Field(default=5, ge=4, le=128)
    max_results: int = Field(default=200, ge=1, le=1000)


class PeRequest(BaseModel):
    file_id: str


class ArtifactsRequest(BaseModel):
    file_id: str


class TimelineRequest(BaseModel):
    file_id: str
    window_seconds: int = Field(default=300, ge=0, le=86400)


class CustodyRegisterRequest(BaseModel):
    file_id: str
    evidence_id: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)
    timestamp: str | None = None


class CustodyAppendRequest(BaseModel):
    record_path: str
    action: str
    actor: str = Field(min_length=1, max_length=128)
    note: str = Field(max_length=2048)
    timestamp: str | None = None


class CustodyVerifyRequest(BaseModel):
    record_path: str
    file_id: str


class RegistryRequest(BaseModel):
    file_id: str


class AcademyHexToBinaryRequest(BaseModel):
    value: str


class AcademyBinaryToHexRequest(BaseModel):
    value: str


class ByteAcademyRequest(BaseModel):
    file_id: str
    offset: int = Field(ge=0)


class EntropyAcademyRequest(BaseModel):
    file_id: str
    section_index: int = Field(ge=0)


class ImportAcademyRequest(BaseModel):
    file_id: str


class RvaAcademyRequest(BaseModel):
    file_id: str
    rva: int = Field(ge=0)


class PeAcademyRequest(BaseModel):
    file_id: str


class ReportWriteRequest(BaseModel):
    file_id: str
    report_mode: str = Field(default="redacted", pattern="^(forense|shareable|redacted)$")
    filename: str = Field(default="hexforge-report.json", pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\\.json$")




# ─── Helper functions ───
def _get_upload_path(file_id: str) -> Path:
    """Resolve only server-issued opaque IDs; never accept client paths."""
    if not re.fullmatch(r"[0-9a-f]{32}", file_id):
        raise HTTPException(status_code=400, detail="Invalid file ID")
    path = UPLOAD_DIR / file_id
    if not path.is_file() or path.is_symlink():
        raise HTTPException(status_code=404, detail="File not found")
    return path


def _validate_origin(request: Request) -> None:
    """Exact loopback Host/Origin validation, with a session-bound API token."""
    host = request.headers.get("host", "")
    allowed_hosts = {f"127.0.0.1:{ACTIVE_PORT}", f"localhost:{ACTIVE_PORT}"}
    if host not in allowed_hosts:
        raise HTTPException(status_code=403, detail="Invalid Host header")
    origin = request.headers.get("origin")
    if origin is not None and origin not in {f"http://{h}" for h in allowed_hosts}:
        raise HTTPException(status_code=403, detail="Invalid Origin header")
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if not secrets.compare_digest(request.headers.get("x-hexforge-token", ""), SESSION_TOKEN):
            raise HTTPException(status_code=403, detail="Invalid local session token")




# ─── Lifespan ───
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _server_instance
    _shutdown_event.clear()
    yield
    _shutdown_event.set()


# ─── FastAPI App ───
app = FastAPI(
    title="NEXA-HexForge Local Console",
    description="Local forensic analysis web interface",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# CORS: only allow localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=[f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ─── Middleware ───
@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Apply exact Host validation to all requests and session token to writes.
    _validate_origin(request)

    # Limit request body size
    content_length = request.headers.get("content-length")
    if content_length and (not content_length.isdecimal() or int(content_length) > MAX_UPLOAD_SIZE + 1048576):
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large"},
        )

    response = await call_next(request)

    # Security headers
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"

    return response


# ─── Routes ───
@app.get("/api/health", response_model=HealthResponse)
async def health():
    return HealthResponse()


@app.get("/api/session")
async def session_token():
    return {"token": SESSION_TOKEN}


@app.post("/api/upload", response_model=FileUploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """Bounded streaming upload; opaque ID, exclusive temporary file."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    file_id = secrets.token_hex(16)
    path = UPLOAD_DIR / file_id
    total = 0
    digest = hashlib.sha256()
    try:
        with path.open("xb") as output:
            os.chmod(path, 0o600)
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="File too large")
                digest.update(chunk)
                output.write(chunk)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return FileUploadResponse(
        file_id=file_id, filename=Path(file.filename).name,
        size=total, sha256=digest.hexdigest()
    )


@app.post("/api/inspect")
async def inspect(request: InspectRequest):
    """Inspect a file: hashes, entropy, magic bytes, preview."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = inspect_file(file_path, preview_bytes=request.preview_bytes, report_mode=request.report_mode)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inspection failed: {e}")


@app.post("/api/hexview")
async def hexview(request: HexViewRequest):
    """Get hex/ASCII rows at a specific offset."""
    file_path = _get_upload_path(request.file_id)
    try:
        rows = hex_rows(file_path, request.offset, request.length, request.width)
        return {"rows": rows}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Hex view failed: {e}")


@app.post("/api/strings")
async def strings(request: StringsRequest):
    """Extract ASCII and UTF-16LE strings."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = extract_strings(file_path, min_length=request.min_length, max_results=request.max_results)
        return {"strings": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"String extraction failed: {e}")


@app.post("/api/pe")
async def pe_inspect(request: PeRequest):
    """Inspect PE structure."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = inspect_pe(file_path)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PE inspection failed: {e}")


@app.post("/api/imports")
async def imports(request: PeRequest):
    """Inspect PE imports."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = inspect_imports(file_path)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Import inspection failed: {e}")


@app.post("/api/indicators")
async def indicators(request: PeRequest):
    """Get section indicators (entropy, writable+executable)."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = section_indicators(file_path)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Indicators failed: {e}")


@app.post("/api/artifacts")
async def artifacts(request: ArtifactsRequest):
    """Load and normalize C1 artifact CSV export."""
    file_path = _get_upload_path(request.file_id)
    try:
        export = load_export(file_path)
        tl = artifacts_timeline(export)
        return {"export": {k: v for k, v in export.items() if k != "records"}, "timeline": tl}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Artifact processing failed: {e}")


@app.post("/api/timeline")
async def timeline(request: TimelineRequest):
    """C2 cross-source correlation."""
    file_path = _get_upload_path(request.file_id)
    try:
        export = load_export(file_path)
        result = correlate(export, request.window_seconds)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Timeline correlation failed: {e}")


@app.post("/api/custody/register")
async def custody_register(request: CustodyRegisterRequest):
    """Register evidence in custody chain."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = register_evidence(
            request.evidence_id,
            file_path,
            request.actor,
            request.timestamp,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Custody registration failed: {e}")


@app.post("/api/custody/append")
async def custody_append(request: CustodyAppendRequest):
    """Append event to custody chain."""
    try:
        record = load_record(request.record_path)
        result = append_event(
            record,
            request.action,
            request.actor,
            request.note,
            request.timestamp,
        )
        # Save back (caller must handle destination)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Custody append failed: {e}")


@app.post("/api/custody/verify")
async def custody_verify(request: CustodyVerifyRequest):
    """Verify evidence against custody record."""
    file_path = _get_upload_path(request.file_id)
    try:
        record = load_record(request.record_path)
        result = verify_evidence(record, file_path)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Custody verification failed: {e}")


@app.post("/api/registry")
async def registry(request: RegistryRequest):
    """Analyze normalized Sysmon registry export."""
    file_path = _get_upload_path(request.file_id)
    try:
        result = analyze_export(file_path)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registry analysis failed: {e}")


# ─── Academy endpoints ───
@app.post("/api/academy/hex2bin")
async def academy_hex2bin(request: AcademyHexToBinaryRequest):
    try:
        return hex_to_binary(request.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/academy/bin2hex")
async def academy_bin2hex(request: AcademyBinaryToHexRequest):
    try:
        return binary_to_hex(request.value)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/academy/byte")
async def academy_byte(request: ByteAcademyRequest):
    file_path = _get_upload_path(request.file_id)
    try:
        return inspect_byte(file_path, request.offset)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Byte inspection failed: {e}")


@app.post("/api/academy/entropy")
async def academy_entropy(request: EntropyAcademyRequest):
    file_path = _get_upload_path(request.file_id)
    try:
        return inspect_section_entropy(file_path, request.section_index)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Entropy analysis failed: {e}")


@app.post("/api/academy/imports")
async def academy_imports(request: ImportAcademyRequest):
    file_path = _get_upload_path(request.file_id)
    try:
        return explain_imports(file_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Import explanation failed: {e}")


@app.post("/api/academy/rva")
async def academy_rva(request: RvaAcademyRequest):
    file_path = _get_upload_path(request.file_id)
    try:
        return inspect_rva(file_path, request.rva)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RVA mapping failed: {e}")


@app.post("/api/academy/pe")
async def academy_pe(request: PeAcademyRequest):
    file_path = _get_upload_path(request.file_id)
    try:
        return explain_pe(file_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PE explanation failed: {e}")


# ─── Report writing ───
@app.post("/api/report/write")
async def report_write(request: ReportWriteRequest):
    """Recompute from server-held evidence, save exclusively to private report dir."""
    file_path = _get_upload_path(request.file_id)
    filename = request.filename
    if filename in (".", "..") or filename.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    destination = REPORT_DIR / filename
    try:
        report = inspect_file(file_path, report_mode=request.report_mode)
        write_report(report, destination)
        return {"status": "ok", "filename": filename, "report_mode": request.report_mode}
    except FileExistsError:
        raise HTTPException(status_code=409, detail="Report already exists")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report request")
    except Exception:
        raise HTTPException(status_code=500, detail="Report export failed")


@app.get("/api/report/download/{filename}")
async def report_download(filename: str):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\\.json", filename):
        raise HTTPException(status_code=400, detail="Invalid report filename")
    path = REPORT_DIR / filename
    if path.is_symlink() or not path.is_file():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=filename, media_type="application/json")


# ─── Server control ───
@app.post("/api/server/stop")
async def server_stop():
    """Stop the server (for launcher integration)."""
    _shutdown_event.set()
    if _server_instance:
        _server_instance.should_exit = True
    return {"status": "stopping"}


# ─── Static file serving (GUI) ───
@app.get("/")
async def root():
    """Serve the main GUI page."""
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>NEXA-HexForge Local Console</h1><p>GUI not built yet.</p>")


@app.get("/{path:path}")
async def serve_static(path: str):
    """Serve static files for the GUI (SPA fallback)."""
    # Prevent path traversal
    if ".." in path or path.startswith("/"):
        raise HTTPException(status_code=404, detail="Not found")

    file_path = static_dir / path
    if file_path.exists() and file_path.is_file():
        return FileResponse(file_path)

    # SPA fallback: serve index.html for unknown routes
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    raise HTTPException(status_code=404, detail="Not found")


# ─── Server control ───
def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, open_browser: bool = True):
    """Run the server in a background thread."""
    global _server_thread, _server_instance, ACTIVE_PORT
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("Only loopback binding is supported")
    ACTIVE_PORT = port

    import uvicorn

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    _server_instance = server

    def run():
        server.run()

    _server_thread = threading.Thread(target=run, daemon=True)
    _server_thread.start()

    # Wait for server to start
    import time
    import socket
    for _ in range(50):
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except ConnectionRefusedError:
            time.sleep(0.1)
    else:
        raise RuntimeError("Server failed to start")

    if open_browser:
        webbrowser.open(f"http://{host}:{port}")

    return server


def stop_server():
    """Stop the server."""
    global _server_instance
    if _server_instance:
        _server_instance.should_exit = True
    _shutdown_event.set()