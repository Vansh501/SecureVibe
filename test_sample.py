# test_sample.py - A realistic vibe-coded mini script
# Test this file with SecureVibe!

import os
import sqlite3

# 1. Exposed Secrets
OPENAI_API_KEY = "sk-proj-9876543210abcdef9876543210abcdef9876543210"
JWT_SECRET_KEY = "my_super_secret_jwt_key_2026"

# 2. Insecure Settings
DEBUG = True
ALLOWED_ORIGINS = ["*"]

def fetch_user_data(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 3. SQL Injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def ping_server(ip_address):
    # 4. Command Injection via os.system
    os.system(f"ping -c 1 {ip_address}")

def get_report(filename):
    # 5. Path Traversal
    filepath = os.path.join("reports", filename)
    with open(filepath, "r") as f:
        return f.read()
