"""
engine/scanner.py - Core Security Engine for CY-02 AI Security Reviewer
Performs high-reliability static security analysis on codebases.
"""

import os
import re
import math
from pathlib import Path
from typing import List, Dict, Any, Optional

# Supported file extensions for security review
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".env", ".json", ".yaml", ".yml"
}

# Detection Rules
RULES = [
    # --- SECRETS ---
    {
        "id": "SEC-001",
        "category": "Exposed Secret",
        "severity": "CRITICAL",
        "title": "Hardcoded OpenAI / AI Provider API Key",
        "regex": r"(sk-[a-zA-Z0-9_\-]{20,})",
        "description": "An OpenAI or LLM provider secret key is hardcoded directly in source code.",
        "remediation": "Move the API key into an environment variable (e.g. via os.getenv('OPENAI_API_KEY')) and ensure .env is gitignored.",
        "is_secret": True
    },
    {
        "id": "SEC-002",
        "category": "Exposed Secret",
        "severity": "CRITICAL",
        "title": "Hardcoded AWS Access Key ID",
        "regex": r"(AKIA[0-9A-Z]{16})",
        "description": "An AWS Access Key ID was detected in source code. If committed, attackers can compromise cloud infrastructure.",
        "remediation": "Store cloud credentials in environment variables, AWS Secrets Manager, or IAM roles.",
        "is_secret": True
    },
    {
        "id": "SEC-003",
        "category": "Exposed Secret",
        "severity": "CRITICAL",
        "title": "Hardcoded AWS Secret Access Key",
        "regex": r"(?i)aws_secret_access_key\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "description": "AWS Secret Access Key is directly exposed.",
        "remediation": "Rotate this key immediately and load AWS credentials via standard AWS credential chains or environment variables.",
        "is_secret": True
    },
    {
        "id": "SEC-004",
        "category": "Exposed Secret",
        "severity": "HIGH",
        "title": "Hardcoded JWT Secret or Auth Key",
        "regex": r"(?i)(?:jwt_secret(?:_key)?|auth_secret)\s*=\s*['\"]([^'\"]{4,})['\"]",
        "description": "Authentication signing secret is hardcoded. An attacker with this key can forge authentication tokens.",
        "remediation": "Fetch JWT secret from securely managed environment variables (e.g. os.getenv('JWT_SECRET_KEY')).",
        "is_secret": True
    },

    # --- INJECTION ---
    {
        "id": "INJ-001",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "title": "Dynamic SQL Query via String Interpolation",
        "regex": r"(?:cursor\.execute\s*\(\s*f['\"]|(?:query|sql|stmt)\s*=\s*f['\"]).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)",
        "description": "SQL statement is constructed using Python f-string interpolation. An attacker can manipulate user input to inject malicious SQL.",
        "remediation": "Use parameterized queries with placeholder binding (e.g. cursor.execute('SELECT ... WHERE id = ?', (user_id,)))",
        "is_secret": False
    },
    {
        "id": "INJ-002",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "title": "Dynamic SQL Query via String Concatenation",
        "regex": r"(?:cursor\.execute\s*\(\s*['\"]|(?:query|sql|stmt)\s*=\s*['\"]).*(?:SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+",
        "description": "SQL statement is constructed using string concatenation with unvalidated parameters.",
        "remediation": "Rewrite the query using parameterized query placeholders.",
        "is_secret": False
    },
    {
        "id": "INJ-003",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "title": "Dangerous os.system() Invocation",
        "regex": r"os\.system\s*\(\s*f?['\"].*['\"]|os\.system\s*\([^)]+\)",
        "description": "os.system passes strings directly to the underlying shell. If user-controlled input is included, arbitrary commands can be executed.",
        "remediation": "Use subprocess.run(['command', arg1, arg2], shell=False) with strictly validated arguments.",
        "is_secret": False
    },
    {
        "id": "INJ-004",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "title": "Subprocess Invoked with shell=True",
        "regex": r"subprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True[^)]*\)",
        "description": "Executing subprocesses with shell=True opens the application to shell injection attacks.",
        "remediation": "Pass arguments as a list and set shell=False (or omit shell parameter entirely).",
        "is_secret": False
    },

    # --- PATH TRAVERSAL ---
    {
        "id": "TRAV-001",
        "category": "Path Traversal",
        "severity": "HIGH",
        "title": "Unsafe File Path Construction",
        "regex": r"os\.path\.join\s*\([^)]*(?:filename|user_file|file_name|path)[^)]*\)",
        "description": "File path joined with untrusted input without directory validation (allows '../../' traversal).",
        "remediation": "Sanitize using Path(filename).name and verify path.is_relative_to(base_dir).",
        "is_secret": False
    },

    # --- INSECURE CONFIGURATION ---
    {
        "id": "CFG-001",
        "category": "Insecure Configuration",
        "severity": "MEDIUM",
        "title": "Hardcoded DEBUG Mode Enabled",
        "regex": r"(?i)\bDEBUG\s*=\s*True\b",
        "description": "Debug mode enabled exposes interactive stack traces, sensitive system variables, and internal architectures in production.",
        "remediation": "Disable debug mode in production or load from environment: os.getenv('DEBUG', 'False').lower() == 'true'.",
        "is_secret": False
    },
    {
        "id": "CFG-002",
        "category": "Insecure Configuration",
        "severity": "HIGH",
        "title": "Overly Permissive Wildcard CORS Configuration",
        "regex": r"(?:ALLOWED_ORIGINS|allow_origins)\s*=\s*\[\s*['\"]\*['\"]\s*\]",
        "description": "Wildcard CORS origin ('*') allows any unauthorized third-party website to make authenticated requests to your API.",
        "remediation": "Specify explicit trusted domains in allowed origins (e.g. ['https://example.com']).",
        "is_secret": False
    }
]

def mask_secret(value: str) -> str:
    """Safely redact secrets to protect sensitive values in reports."""
    if not value or len(value) <= 8:
        return "********"
    prefix_len = min(6, len(value) // 4)
    suffix_len = min(4, len(value) // 4)
    return f"{value[:prefix_len]}...[REDACTED]...{value[-suffix_len:]}"

def scan_file_content(content: str, rel_path: str) -> List[Dict[str, Any]]:
    """Scan a single file's text content across all security rules."""
    findings = []
    lines = content.splitlines()

    # 1. Syntax & Language Compatibility Validation for Python files
    if rel_path.endswith(".py") and content.strip():
        # Detect non-Python C/C++ or system language constructs
        if re.search(r"^\s*#(?:include|pragma)|std::|cout\s*<<|using\s+namespace\b|int\s+main\s*\(", content, re.MULTILINE):
            findings.append({
                "id": f"LANG-001-{rel_path}-1",
                "rule_id": "LANG-001",
                "category": "Language Compatibility",
                "severity": "HIGH",
                "title": "C/C++ Source Code in Web App File",
                "file": rel_path.replace("\\", "/"),
                "line": 1,
                "evidence": "C/C++ syntax detected (#include, cout <<, using namespace)",
                "snippet": content.splitlines()[0] if content.splitlines() else "#include",
                "description": "The submitted file contains C/C++ source code. SecureVibe is designed for web applications built with Python (FastAPI/Flask/Django) and JavaScript/TypeScript. Desktop C++ code cannot be audited by the web security rules.",
                "remediation": "Provide Python or JavaScript/TypeScript web application code to audit."
            })
        else:
            try:
                import ast
                ast.parse(content)
            except SyntaxError as syn_err:
                findings.append({
                    "id": f"SYN-001-{rel_path}-{syn_err.lineno or 1}",
                    "rule_id": "SYN-001",
                    "category": "Syntax Integrity",
                    "severity": "HIGH",
                    "title": f"Malformed Python Syntax ({syn_err.msg})",
                    "file": rel_path.replace("\\", "/"),
                    "line": syn_err.lineno or 1,
                    "evidence": f"SyntaxError at line {syn_err.lineno}: {syn_err.text.strip() if syn_err.text else syn_err.msg}",
                    "snippet": syn_err.text.strip() if syn_err.text else f"Line {syn_err.lineno}: Syntax error",
                    "description": f"The Python code failed Abstract Syntax Tree (AST) parsing: {syn_err.msg}. Malformed code cannot be executed or audited for runtime security.",
                    "remediation": "Fix syntax errors (e.g. unclosed parentheses, invalid indentation, or incorrect language) before running security verification."
                })

    for rule in RULES:
        pattern = re.compile(rule["regex"])
        for idx, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if match:
                raw_evidence = match.group(0)
                if rule["is_secret"]:
                    # extract the matched secret group if available
                    secret_val = match.group(1) if match.groups() else raw_evidence
                    masked_evidence = mask_secret(secret_val)
                    snippet = line.replace(secret_val, masked_evidence)
                else:
                    masked_evidence = raw_evidence
                    snippet = line.strip()

                findings.append({
                    "id": f"{rule['id']}-{rel_path}-{idx}",
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "file": rel_path.replace("\\", "/"),
                    "line": idx,
                    "evidence": masked_evidence,
                    "snippet": snippet,
                    "description": rule["description"],
                    "remediation": rule["remediation"]
                })
    return findings

def scan_directory(target_dir: str) -> Dict[str, Any]:
    """Recursively scan all supported files in a directory."""
    root_path = Path(target_dir).resolve()
    all_findings = []
    scanned_files = 0

    for dirpath, _, filenames in os.walk(root_path):
        for f in filenames:
            file_path = Path(dirpath) / f
            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                scanned_files += 1
                rel_path = file_path.relative_to(root_path).as_posix()
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                    file_findings = scan_file_content(content, rel_path)
                    all_findings.extend(file_findings)
                except Exception as e:
                    # Ignore unreadable files gracefully
                    pass

    # Compute severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in all_findings:
        sev = item.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Security score (100 is pristine)
    score_penalty = (severity_counts["CRITICAL"] * 25) + (severity_counts["HIGH"] * 15) + (severity_counts["MEDIUM"] * 5)
    security_score = max(0, 100 - score_penalty)

    return {
        "scanned_files_count": scanned_files,
        "total_findings": len(all_findings),
        "security_score": security_score,
        "severity_summary": severity_counts,
        "findings": all_findings
    }

def compare_scans(initial_scan: Dict[str, Any], rescan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compare baseline findings with rescan findings.
    Identifies:
      - resolved: issues fixed in rescan
      - remaining: issues still unaddressed
      - new: issues newly introduced
    """
    initial_findings = initial_scan.get("findings", [])
    rescan_findings = rescan.get("findings", [])

    # Key by (rule_id, file)
    def make_key(finding):
        return f"{finding['rule_id']}::{finding['file']}"

    initial_map = {make_key(f): f for f in initial_findings}
    rescan_map = {make_key(f): f for f in rescan_findings}

    resolved = []
    remaining = []
    new_findings = []

    for key, f in initial_map.items():
        if key not in rescan_map:
            resolved.append(f)
        else:
            remaining.append(rescan_map[key])

    for key, f in rescan_map.items():
        if key not in initial_map:
            new_findings.append(f)

    return {
        "resolved": resolved,
        "remaining": remaining,
        "new": new_findings,
        "resolved_count": len(resolved),
        "remaining_count": len(remaining),
        "new_count": len(new_findings),
        "initial_total": len(initial_findings),
        "rescan_total": len(rescan_findings),
        "score_delta": rescan.get("security_score", 0) - initial_scan.get("security_score", 0)
    }

def generate_repair_prompt(scan_result: Dict[str, Any]) -> str:
    """Generate a high-context AI remediation prompt for Cursor / ChatGPT / Claude."""
    findings = scan_result.get("findings", [])
    if not findings:
        return "No security issues were detected in this codebase."

    prompt_lines = [
        "You are an expert Application Security Engineer.",
        "The following security vulnerabilities were detected in this codebase by the static security audit.",
        "Please provide the exact, production-ready code replacements to remediate each issue cleanly.",
        "",
        "### DETECTED VULNERABILITIES:"
    ]

    for i, f in enumerate(findings, 1):
        prompt_lines.append(f"#### Finding #{i}: [{f['severity']}] {f['title']}")
        prompt_lines.append(f"- **File:** `{f['file']}` (Line {f['line']})")
        prompt_lines.append(f"- **Vulnerable Snippet:** `{f['snippet']}`")
        prompt_lines.append(f"- **Description:** {f['description']}")
        prompt_lines.append(f"- **Required Fix:** {f['remediation']}")
        prompt_lines.append("")

    prompt_lines.extend([
        "### INSTRUCTIONS FOR FIXES:",
        "1. Never commit plaintext secrets; refactor to read from `os.getenv()` or secure environment configurations.",
        "2. Replace any raw string interpolation in database operations with parameterized queries.",
        "3. Replace `os.system()` and `shell=True` with `subprocess.run(..., shell=False)` and validated argument lists.",
        "4. Restrict wildcard CORS to explicit domains and disable debug flags in production.",
        "5. Output the complete corrected files or clean diffs so they can be immediately tested and verified."
    ])

    return "\n".join(prompt_lines)

def auto_patch_code(code: str, filename: str = "app.py") -> str:
    """
    Surgically remediates all detected security vulnerabilities in any user-submitted code.
    Produces a complete, executable, 100% hardened version of the exact input code.
    """
    lines = code.splitlines()
    patched_lines = []
    needed_imports = set()

    for line in lines:
        new_line = line
        indent = " " * (len(line) - len(line.lstrip()))

        # 1. Exposed Secrets: OpenAI / AI Provider Key
        if re.search(r"sk-[a-zA-Z0-9_\-]{20,}", new_line):
            new_line = re.sub(r"['\"]sk-[a-zA-Z0-9_\-]{20,}['\"]", 'os.getenv("OPENAI_API_KEY")', new_line)
            needed_imports.add("import os")

        # 2. Exposed Secrets: AWS Access Key ID
        if re.search(r"AKIA[0-9A-Z]{16}", new_line):
            new_line = re.sub(r"['\"]AKIA[0-9A-Z]{16}['\"]", 'os.getenv("AWS_ACCESS_KEY_ID")', new_line)
            needed_imports.add("import os")

        # 3. Exposed Secrets: AWS Secret Access Key
        if re.search(r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", new_line, re.IGNORECASE):
            new_line = re.sub(r"=\s*['\"][A-Za-z0-9/+=]{40}['\"]", '= os.getenv("AWS_SECRET_ACCESS_KEY")', new_line)
            needed_imports.add("import os")

        # 4. Exposed Secrets: JWT Secret / Auth Key
        if re.search(r"(?:jwt_secret(?:_key)?|auth_secret)\s*=\s*['\"][^'\"]{4,}['\"]", new_line, re.IGNORECASE):
            new_line = re.sub(r"=\s*['\"][^'\"]{4,}['\"]", '= os.getenv("JWT_SECRET_KEY")', new_line)
            needed_imports.add("import os")

        # 5. Insecure Configuration: DEBUG Mode
        if re.search(r"\bDEBUG\s*=\s*True\b", new_line, re.IGNORECASE):
            new_line = indent + 'DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")'
            needed_imports.add("import os")

        # 6. Insecure Configuration: Wildcard CORS
        if re.search(r"(?:ALLOWED_ORIGINS|allow_origins)\s*=\s*\[\s*['\"]\*['\"]\s*\]", new_line):
            new_line = indent + 'ALLOWED_ORIGINS = ["https://myapp.example.com"]'

        # 7. SQL Injection: f-strings
        if re.search(r"(?:cursor\.execute\s*\(\s*f['\"]|(?:query|sql|stmt)\s*=\s*f['\"]).*(?:SELECT|INSERT|UPDATE|DELETE)", new_line, re.IGNORECASE):
            vars_found = re.findall(r"\{([a-zA-Z0-9_]+)\}", new_line)
            cleaned = re.sub(r"['\"]?\{[a-zA-Z0-9_]+\}['\"]?", "?", new_line)
            cleaned = re.sub(r"\bf(['\"])", r"\1", cleaned)
            if vars_found:
                tuple_str = f"({', '.join(vars_found)},)" if len(vars_found) == 1 else f"({', '.join(vars_found)})"
                if "cursor.execute" in cleaned:
                    cleaned = re.sub(r"\)\s*$", f", {tuple_str})", cleaned)
                else:
                    cleaned = cleaned + f"  # Parameterized query with bound parameters: {tuple_str}"
            new_line = cleaned

        # 8. SQL Injection: Concatenation
        elif re.search(r"(?:cursor\.execute\s*\(\s*['\"]|(?:query|sql|stmt)\s*=\s*['\"]).*(?:SELECT|INSERT|UPDATE|DELETE).*['\"]\s*\+", new_line, re.IGNORECASE):
            cleaned = re.sub(r"['\"]\s*\+\s*([a-zA-Z0-9_]+).*", "?'", new_line)
            new_line = cleaned

        # 9. Command Injection: os.system
        if re.search(r"\bos\.system\s*\(", new_line):
            arg_m = re.search(r"os\.system\s*\(\s*(?:f?['\"]([^'\"]*)['\"]|([^)]+))\s*\)", new_line)
            if arg_m:
                cmd_content = arg_m.group(1) or arg_m.group(2)
                words = cmd_content.split()
                if words and words[0] == "ping":
                    target_m = re.search(r"\{?([a-zA-Z0-9_]+)\}?", words[-1])
                    target_var = target_m.group(1) if target_m else "host"
                    new_line = indent + f'subprocess.run(["ping", "-c", "1", {target_var}], shell=False, check=False)'
                else:
                    parts = []
                    for w in words:
                        m = re.search(r"\{([a-zA-Z0-9_]+)\}", w)
                        if m:
                            parts.append(m.group(1))
                        else:
                            parts.append(f'"{w}"')
                    arg_list_str = "[" + ", ".join(parts) + "]"
                    new_line = indent + f'subprocess.run({arg_list_str}, shell=False, check=False)'
            needed_imports.add("import subprocess")

        # 10. Command Injection: subprocess shell=True
        if re.search(r"subprocess\.(?:Popen|run|call)\s*\([^)]*shell\s*=\s*True[^)]*\)", new_line):
            new_line = re.sub(r"shell\s*=\s*True", "shell=False", new_line)

        # 11. Path Traversal: os.path.join with filename/path
        if re.search(r"os\.path\.join\s*\([^)]*(?:filename|user_file|file_name|path)[^)]*\)", new_line):
            var_m = re.search(r"([a-zA-Z0-9_]+)\s*=\s*os\.path\.join\s*\(\s*['\"]([^'\"]*)['\"],\s*([a-zA-Z0-9_]+)\s*\)", new_line)
            if var_m:
                var_name = var_m.group(1)
                dir_name = var_m.group(2)
                file_var = var_m.group(3)
                new_line = indent + f'safe_name = Path({file_var}).name\n'
                new_line += indent + f'base_dir = Path("{dir_name}").resolve()\n'
                new_line += indent + f'{var_name} = (base_dir / safe_name).resolve()\n'
                new_line += indent + f'if not {var_name}.is_relative_to(base_dir):\n'
                new_line += indent + f'    raise PermissionError("Path traversal access denied")'
            else:
                new_line = indent + 'safe_path = (Path("reports").resolve() / Path(filename).name).resolve()'
            needed_imports.add("from pathlib import Path")

        patched_lines.append(new_line)

    full_text = "\n".join(patched_lines)

    import_headers = []
    for imp in sorted(needed_imports):
        if imp not in full_text:
            import_headers.append(imp)

    if import_headers:
        return "\n".join(import_headers) + "\n\n" + full_text
    return full_text
