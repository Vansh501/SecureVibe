# app.py - Secured Web Application
import os
import subprocess
from pathlib import Path
from config import DEBUG, HOST, PORT, ALLOWED_ORIGINS, JWT_SECRET_KEY
from database import authenticate_user, search_products

BASE_UPLOAD_DIR = Path("user_uploads").resolve()

def run_diagnostics(target_host):
    # SECURE: Argument list execution without invoking system shell
    # Basic input check
    if not target_host or any(char in target_host for char in ";|&$`"):
        raise ValueError("Invalid target host format")
    subprocess.run(["ping", "-c", "1", target_host], shell=False, check=False)

def read_user_file(filename):
    # SECURE: Prevent path traversal by validating filename against allowed base directory
    safe_filename = Path(filename).name
    target_path = (BASE_UPLOAD_DIR / safe_filename).resolve()
    
    if not target_path.is_relative_to(BASE_UPLOAD_DIR):
        raise PermissionError("Access outside designated directory denied")
    
    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()

def execute_helper_tool(command_arg):
    # SECURE: Subprocess call with explicit argument list and shell=False
    subprocess.run(["tool", "--param", command_arg], shell=False, check=False)

if __name__ == "__main__":
    print(f"Starting server on {HOST}:{PORT} with DEBUG={DEBUG}")
