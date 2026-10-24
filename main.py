"""
main.py - FastAPI Application for CY-02 AI Security Reviewer
Serves the REST API and the interactive developer dashboard.
"""

import os
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from engine.scanner import scan_directory, compare_scans, generate_repair_prompt, auto_patch_code
from engine.ai_providers import PROVIDERS, generate_remediation

app = FastAPI(
    title="SecureVibe - AI Security Reviewer",
    description="Static application security testing and AI-powered remediation verification for vibe-coded applications.",
    version="1.0.0"
)

# CORS middleware for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent.resolve()
STATIC_DIR = BASE_DIR / "static"
BENCHMARK_DIR = BASE_DIR / "benchmark"
TEMP_UPLOADS = BASE_DIR / "temp_sessions"
TEMP_UPLOADS.mkdir(exist_ok=True)

# In-memory session cache for scan histories (session_id -> dict)
SESSIONS: Dict[str, Dict[str, Any]] = {}

def ensure_benchmark_zips():
    """Create downloadable ZIP bundles of the benchmark suites for live judging testing."""
    vuln_zip = BENCHMARK_DIR / "vulnerable_sample.zip"
    secured_zip = BENCHMARK_DIR / "secured_sample.zip"
    
    if not vuln_zip.exists():
        vuln_src = BENCHMARK_DIR / "vulnerable_project"
        with zipfile.ZipFile(vuln_zip, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(vuln_src):
                for f in files:
                    full_p = Path(root) / f
                    arcname = full_p.relative_to(vuln_src)
                    z.write(full_p, arcname)

    if not secured_zip.exists():
        sec_src = BENCHMARK_DIR / "secured_project"
        with zipfile.ZipFile(secured_zip, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(sec_src):
                for f in files:
                    full_p = Path(root) / f
                    arcname = full_p.relative_to(sec_src)
                    z.write(full_p, arcname)

ensure_benchmark_zips()

@app.get("/api/benchmark/vulnerable")
async def get_vulnerable_benchmark():
    """Instantly scan the vulnerable benchmark codebase."""
    vuln_path = BENCHMARK_DIR / "vulnerable_project"
    results = scan_directory(str(vuln_path))
    results["projectName"] = "Deliberately Vulnerable Sample"
    return results

@app.get("/api/benchmark/secured")
async def get_secured_benchmark():
    """Instantly scan the secured/corrected benchmark codebase."""
    sec_path = BENCHMARK_DIR / "secured_project"
    results = scan_directory(str(sec_path))
    results["projectName"] = "Secured Sample (Corrected)"
    return results

@app.get("/api/benchmark/diff")
async def get_benchmark_diff():
    """Return the comparison between vulnerable and secured benchmarks."""
    vuln_path = BENCHMARK_DIR / "vulnerable_project"
    sec_path = BENCHMARK_DIR / "secured_project"
    
    vuln_scan = scan_directory(str(vuln_path))
    sec_scan = scan_directory(str(sec_path))
    diff = compare_scans(vuln_scan, sec_scan)
    return {
        "initial": vuln_scan,
        "rescan": sec_scan,
        "diff": diff
    }

@app.get("/api/benchmark/download/{filename}")
async def download_benchmark(filename: str):
    """Download the sample project ZIPs for manual testing."""
    target_file = BENCHMARK_DIR / filename
    if not target_file.exists():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(target_file, filename=filename, media_type="application/zip")

@app.post("/api/scan/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    """
    Upload a ZIP archive of a project or single source file.
    Extracts, scans, and stores session for subsequent re-scanning.
    """
    import uuid
    session_id = str(uuid.uuid4())[:8]
    session_dir = TEMP_UPLOADS / session_id / "initial"
    session_dir.mkdir(parents=True, exist_ok=True)

    file_bytes = await file.read()
    filename = file.filename or "upload.zip"

    if filename.endswith(".zip"):
        zip_path = session_dir / "uploaded.zip"
        with open(zip_path, "wb") as f:
            f.write(file_bytes)
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(session_dir)
            zip_path.unlink() # remove archive after extracting
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Corrupt ZIP file: {str(e)}")
    else:
        # Single code file
        safe_path = session_dir / filename
        with open(safe_path, "wb") as f:
            f.write(file_bytes)

    scan_result = scan_directory(str(session_dir))
    scan_result["session_id"] = session_id
    scan_result["filename"] = filename

    # Cache scan in session
    SESSIONS[session_id] = {
        "initial_scan": scan_result,
        "initial_dir": str(session_dir)
    }

    return scan_result

@app.post("/api/scan/snippet")
async def scan_snippet(payload: Dict[str, Any]):
    """
    Accepts raw pasted code and runs the security scanner directly.
    """
    code = payload.get("code", "")
    filename = payload.get("filename", "snippet.py")
    if not code.strip():
        raise HTTPException(status_code=400, detail="Code snippet cannot be empty.")

    import uuid
    session_id = str(uuid.uuid4())[:8]
    session_dir = TEMP_UPLOADS / session_id / "initial"
    session_dir.mkdir(parents=True, exist_ok=True)

    safe_path = session_dir / filename
    with open(safe_path, "w", encoding="utf-8") as f:
        f.write(code)

    scan_result = scan_directory(str(session_dir))
    scan_result["session_id"] = session_id
    scan_result["filename"] = filename
    scan_result["projectName"] = f"Pasted Snippet ({filename})"

    SESSIONS[session_id] = {
        "initial_scan": scan_result,
        "initial_dir": str(session_dir)
    }

    return scan_result

def get_or_restore_session(session_id: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Retrieve session from RAM or seamlessly recover from disk if server reloaded."""
    # 1. Direct hit in RAM
    if session_id and session_id in SESSIONS:
        return session_id, SESSIONS[session_id]

    # 2. Check if specific session directory exists on disk
    if session_id:
        sess_init_dir = TEMP_UPLOADS / session_id / "initial"
        if sess_init_dir.exists():
            initial_scan = scan_directory(str(sess_init_dir))
            SESSIONS[session_id] = {
                "initial_scan": initial_scan,
                "initial_dir": str(sess_init_dir)
            }
            return session_id, SESSIONS[session_id]

    # 3. Fallback: Find the most recent active session directory on disk
    try:
        available_sessions = sorted(
            [p for p in TEMP_UPLOADS.iterdir() if p.is_dir() and (p / "initial").exists()],
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        if available_sessions:
            latest = available_sessions[0]
            rec_id = latest.name
            sess_init_dir = latest / "initial"
            initial_scan = scan_directory(str(sess_init_dir))
            SESSIONS[rec_id] = {
                "initial_scan": initial_scan,
                "initial_dir": str(sess_init_dir)
            }
            return rec_id, SESSIONS[rec_id]
    except Exception:
        pass

    return None, None

@app.delete("/api/scan/session/{session_id}")
async def clear_session(session_id: str):
    """Remove an uploaded project session and delete its temporary files."""
    if session_id in SESSIONS:
        SESSIONS.pop(session_id, None)
    sess_dir = TEMP_UPLOADS / session_id
    if sess_dir.exists():
        shutil.rmtree(sess_dir, ignore_errors=True)
    return {"status": "cleared", "session_id": session_id}

@app.post("/api/scan/rescan")
async def upload_rescan(session_id: str = Form(...), file: UploadFile = File(...)):
    """
    Upload the corrected project and verify whether reported vulnerabilities are fixed.
    """
    resolved_id, session_data = get_or_restore_session(session_id)
    if not session_data or not resolved_id:
        raise HTTPException(status_code=400, detail="No active scan found. Please paste or upload your original code first.")

    session_dir = TEMP_UPLOADS / resolved_id / "rescan"
    session_dir.mkdir(parents=True, exist_ok=True)

    file_bytes = await file.read()
    filename = file.filename or "rescan.zip"

    if filename.endswith(".zip"):
        zip_path = session_dir / "rescan.zip"
        with open(zip_path, "wb") as f:
            f.write(file_bytes)
        try:
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(session_dir)
            zip_path.unlink()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Corrupt ZIP file: {str(e)}")
    else:
        safe_path = session_dir / filename
        with open(safe_path, "wb") as f:
            f.write(file_bytes)

    rescan_result = scan_directory(str(session_dir))
    initial_scan = session_data["initial_scan"]

    diff_report = compare_scans(initial_scan, rescan_result)
    return {
        "session_id": resolved_id,
        "initial": initial_scan,
        "rescan": rescan_result,
        "diff": diff_report
    }

@app.post("/api/scan/rescan-snippet")
async def rescan_snippet(payload: Dict[str, Any]):
    """
    Accepts raw corrected/fixed code and verifies whether reported vulnerabilities were resolved.
    """
    session_id = payload.get("session_id")
    code = payload.get("code", "")
    filename = payload.get("filename", "snippet.py")
    if not code.strip():
        raise HTTPException(status_code=400, detail="Rescan code snippet cannot be empty.")

    resolved_id, session_data = get_or_restore_session(session_id)
    if not session_data or not resolved_id:
        raise HTTPException(status_code=400, detail="No active scan baseline found. Please paste and audit your original code in 'Upload or Paste Code' first.")

    session_dir = TEMP_UPLOADS / resolved_id / "rescan"
    session_dir.mkdir(parents=True, exist_ok=True)

    safe_path = session_dir / filename
    with open(safe_path, "w", encoding="utf-8") as f:
        f.write(code)

    rescan_result = scan_directory(str(session_dir))
    initial_scan = session_data["initial_scan"]

    diff_report = compare_scans(initial_scan, rescan_result)
    return {
        "session_id": resolved_id,
        "initial": initial_scan,
        "rescan": rescan_result,
        "diff": diff_report
    }

@app.post("/api/scan/auto-fix")
async def generate_auto_fix(payload: Dict[str, Any]):
    """
    Takes the active session or submitted code and dynamically generates
    the complete, fully remediated, 100% secure version of the user's exact code.
    """
    session_id = payload.get("session_id")
    code = payload.get("code")
    filename = payload.get("filename", "app.py")

    resolved_id, session_data = get_or_restore_session(session_id)
    if not code and session_data:
        init_dir = Path(session_data["initial_dir"])
        for file_p in init_dir.glob("**/*"):
            if file_p.is_file() and file_p.suffix in {".py", ".js", ".ts", ".env"}:
                code = file_p.read_text(encoding="utf-8", errors="ignore")
                filename = file_p.name
                break

    if not code or not code.strip():
        raise HTTPException(status_code=400, detail="No source code available to patch.")

    fixed_code = auto_patch_code(code, filename)
    return {
        "success": True,
        "filename": filename,
        "original_code": code,
        "fixed_code": fixed_code
    }

@app.post("/api/ai/repair-prompt")
async def get_repair_prompt(payload: Dict[str, Any]):
    """Generate structured AI remediation prompt from findings."""
    prompt = generate_repair_prompt(payload)
    return {"prompt": prompt}

@app.get("/api/ai/providers")
async def get_providers():
    """Return available AI providers and their configuration."""
    return {
        "providers": [
            {
                "id": pid,
                "name": pdata["name"],
                "description": pdata["description"],
                "models": pdata["models"],
                "default_model": pdata["default_model"],
                "has_env_key": bool(os.getenv(pdata["env_key"])) if pdata.get("env_key") else True
            }
            for pid, pdata in PROVIDERS.items()
        ]
    }

@app.post("/api/ai/generate-fix")
async def generate_ai_fix(payload: Dict[str, Any]):
    """
    Generate live AI remediation using the selected provider (Gemini, OpenAI, Claude, Groq, or Offline).
    """
    findings = payload.get("findings", [])
    provider = payload.get("provider", "offline")
    model = payload.get("model")
    api_key = payload.get("api_key")
    perspective = payload.get("perspective", "dual")

    result = await generate_remediation(
        findings=findings,
        provider=provider,
        model=model,
        api_key=api_key,
        perspective=perspective
    )
    return result

# Mount static folder
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
