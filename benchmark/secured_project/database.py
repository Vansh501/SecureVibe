# database.py - Secured Database Queries with Parameterization
import sqlite3

def get_db_connection():
    conn = sqlite3.connect("database.db")
    return conn

def authenticate_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: Using parameterized queries to prevent SQL Injection
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def search_products(keyword):
    conn = get_db_connection()
    cursor = conn.cursor()
    # SECURE: Safe parameterized query with wildcards passed as parameter
    query = "SELECT * FROM products WHERE name LIKE ?"
    search_param = f"%{keyword}%"
    cursor.execute(query, (search_param,))
    results = cursor.fetchall()
    conn.close()
    return results
