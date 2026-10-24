# config.py - Secured Configuration
import os

# Secure defaults: debug disabled in production
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))

# Secrets safely retrieved from environment variables
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

# Strict, explicit CORS configuration
ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com"
]
ALLOW_CREDENTIALS = True
