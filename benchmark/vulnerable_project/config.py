# config.py - Vulnerable Configuration
# Vibe-coded prototype configuration with hardcoded credentials and unsafe settings

DEBUG = True
HOST = "0.0.0.0"
PORT = 8000

# Hardcoded API Keys & Secrets
OPENAI_API_KEY = "sk-proj-abc1234567890def1234567890abcdef1234567890abc"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET_KEY = "supersecretjwtkey123"

# Wildcard CORS allowing everything
ALLOWED_ORIGINS = ["*"]
ALLOW_CREDENTIALS = True
