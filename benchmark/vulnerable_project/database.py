# database.py - Vulnerable Database Queries
import sqlite3

def get_db_connection():
    conn = sqlite3.connect("database.db")
    return conn

def authenticate_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    # VULNERABILITY: Raw string interpolation leading to SQL Injection (SQLi)
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def search_products(keyword):
    conn = get_db_connection()
    cursor = conn.cursor()
    # VULNERABILITY: Formatted string query in search
    query = "SELECT * FROM products WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return results
