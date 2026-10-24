# app.py - Vulnerable Web Application (FastAPI/Flask style prototype)
import os
import subprocess
from config import DEBUG, HOST, PORT, ALLOWED_ORIGINS, JWT_SECRET_KEY
from database import authenticate_user, search_products

def run_diagnostics(target_host):
    # VULNERABILITY: OS Command Injection via unvalidated shell input
    os.system(f"ping -c 1 {target_host}")

def read_user_file(filename):
    # VULNERABILITY: Path Traversal (Arbitrary File Read)
    filepath = os.path.join("user_uploads", filename)
    with open(filepath, "r") as f:
        return f.read()

def execute_helper_tool(command_arg):
    # VULNERABILITY: Subprocess execution with shell=True
    subprocess.Popen(f"tool --param {command_arg}", shell=True)

if __name__ == "__main__":
    print(f"Starting server on {HOST}:{PORT} with DEBUG={DEBUG}")
