# test_sample_fixed.py - The properly secured version
# Test this file to see a 100/100 score with zero vulnerabilities!

import os
import sqlite3
from pathlib import Path

# 1. Secrets loaded from environment variables (No hardcoded keys)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# 2. Secure production configuration
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
ALLOWED_ORIGINS = ["https://myapp.example.com"]

BASE_REPORTS_DIR = Path("reports").resolve()

def fetch_user_data(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 3. Parameterized query (Prevents SQL Injection)
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

def ping_server(ip_address):
    # 4. Safe argument execution without system shell (Prevents Command Injection)
    import subprocess
    if not ip_address or any(char in ip_address for char in ";|&$`"):
        raise ValueError("Invalid IP address format")
    subprocess.run(["ping", "-c", "1", ip_address], shell=False, check=False)

def get_report(filename):
    # 5. Directory sandboxing (Prevents Path Traversal)
    safe_name = Path(filename).name
    target_path = (BASE_REPORTS_DIR / safe_name).resolve()
    if not target_path.is_relative_to(BASE_REPORTS_DIR):
        raise PermissionError("Access outside designated directory denied")
    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()
