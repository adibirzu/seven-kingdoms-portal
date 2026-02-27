"""Seven Kingdoms Portal - Vulnerable Web Application for Detection Engineering.

A full-featured web portal with intentional vulnerabilities across the OWASP
Top 10 (2021) categories.  Each vulnerability generates rich OpenTelemetry
spans with security.* attributes suitable for building OCI APM / Log Analytics
detection rules.

Integration points:
    - GOAD Active Directory (LDAP bind for authentication)
    - GOAD MSSQL databases (real SQL queries when reachable)
    - OCI APM (traces with security span attributes)
    - OCI Logging (structured log entries with trace correlation)
    - Caldera / Management Agent (host-level telemetry)

Mounted at /portal/ in the main FastAPI app.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import subprocess
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

import warnings
import httpx
import jwt
import pymssql

# Suppress PyJWT short-key warning — the weak secret is intentional for this vuln app
warnings.filterwarnings("ignore", message=".*HMAC key.*below the minimum.*", category=Warning)
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from opentelemetry import trace
from pathlib import Path

from .otel_security import security_span, detection_event
from .detection_rules import DETECTION_RULES

logger = logging.getLogger("Portal")

# ── Configuration ──────────────────────────────────────────────────
STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"

# JWT config - intentionally weak for vulnerability demonstration
JWT_SECRET = os.getenv("PORTAL_JWT_SECRET", "seven-kingdoms-secret-key-2024")
JWT_ALGORITHM = "HS256"  # Also accepts 'none' for vuln demo

# GOAD LDAP endpoints (Active Directory)
LDAP_SERVERS = [
    {"host": "192.168.56.10", "domain": "sevenkingdoms.local", "name": "kingslanding"},
    {"host": "192.168.56.11", "domain": "north.sevenkingdoms.local", "name": "winterfell"},
    {"host": "192.168.56.12", "domain": "essos.local", "name": "meereen"},
]

# GOAD MSSQL endpoints
MSSQL_SERVERS = {
    "castelblack": {"host": "192.168.56.22", "port": 1433, "db": "master"},
    "braavos": {"host": "192.168.56.23", "port": 1433, "db": "master"},
}

# Tracer
tracer = trace.get_tracer("portal.vulnerability")

# ── In-Memory Data Store (simulates real DB) ───────────────────────
USERS_DB: dict[str, dict] = {
    "jon.snow": {
        "id": 1, "username": "jon.snow", "email": "jon@winterfell.north",
        "password_hash": hashlib.md5(b"ghost123").hexdigest(),  # Intentionally weak: MD5
        "role": "user", "realm": "north.sevenkingdoms.local",
        "full_name": "Jon Snow", "title": "Lord Commander",
    },
    "daenerys.targaryen": {
        "id": 2, "username": "daenerys.targaryen", "email": "daenerys@meereen.essos",
        "password_hash": hashlib.md5(b"dracarys").hexdigest(),
        "role": "admin", "realm": "essos.local",
        "full_name": "Daenerys Targaryen", "title": "Mother of Dragons",
    },
    "tyrion.lannister": {
        "id": 3, "username": "tyrion.lannister", "email": "tyrion@kingslanding.local",
        "password_hash": hashlib.md5(b"wine4ever").hexdigest(),
        "role": "user", "realm": "sevenkingdoms.local",
        "full_name": "Tyrion Lannister", "title": "Hand of the Queen",
    },
    "cersei.lannister": {
        "id": 4, "username": "cersei.lannister", "email": "cersei@kingslanding.local",
        "password_hash": hashlib.md5(b"power!").hexdigest(),
        "role": "admin", "realm": "sevenkingdoms.local",
        "full_name": "Cersei Lannister", "title": "Queen of the Seven Kingdoms",
    },
    "arya.stark": {
        "id": 5, "username": "arya.stark", "email": "arya@winterfell.north",
        "password_hash": hashlib.md5(b"needle").hexdigest(),
        "role": "user", "realm": "north.sevenkingdoms.local",
        "full_name": "Arya Stark", "title": "No One",
    },
    "admin": {
        "id": 0, "username": "admin", "email": "admin@sevenkingdoms.local",
        "password_hash": hashlib.md5(b"admin").hexdigest(),  # Default creds!
        "role": "superadmin", "realm": "sevenkingdoms.local",
        "full_name": "System Administrator", "title": "Master of Whispers",
    },
}

MESSAGES_DB: list[dict] = [
    {"id": 1, "from": "cersei.lannister", "to": "tyrion.lannister", "subject": "Payment Overdue",
     "body": "The Iron Bank will have its due. Transfer 10,000 gold dragons immediately.",
     "timestamp": "2024-01-15T10:30:00Z", "read": False},
    {"id": 2, "from": "jon.snow", "to": "daenerys.targaryen", "subject": "Night King Sighting",
     "body": "The army of the dead marches south. We need dragons. SECRET: FLAG{R4V3N_1NT3RC3PT}",
     "timestamp": "2024-01-16T08:00:00Z", "read": True},
    {"id": 3, "from": "admin", "to": "admin", "subject": "System Credentials Backup",
     "body": "DB password: WinterIsComing2024!\nLDAP bind: cn=admin,dc=sevenkingdoms,dc=local / Passw0rd!\nSSH key: /opt/keys/id_rsa",
     "timestamp": "2024-01-10T03:00:00Z", "read": True},
]

TREASURY_DB: list[dict] = [
    {"id": 1001, "house": "Lannister", "type": "income", "amount": 50000, "description": "Gold mines of Casterly Rock", "approver": "tyrion.lannister"},
    {"id": 1002, "house": "Stark", "type": "expense", "amount": 12000, "description": "Wall fortifications", "approver": "jon.snow"},
    {"id": 1003, "house": "Targaryen", "type": "expense", "amount": 75000, "description": "Dragon feeding - classified", "approver": "daenerys.targaryen", "secret": "FLAG{7R345URY_4CC355}"},
    {"id": 1004, "house": "Crown", "type": "debt", "amount": 3000000, "description": "Iron Bank of Braavos loan", "approver": "cersei.lannister"},
    {"id": 1005, "house": "Stark", "type": "expense", "amount": -500, "description": "Refund for defective armor", "approver": "arya.stark"},
]

SESSIONS: dict[str, dict] = {}  # session_id -> {username, role, created_at, ...}

# Active login attempts for brute force tracking
LOGIN_ATTEMPTS: dict[str, list[float]] = {}

# ── Helper Functions ───────────────────────────────────────────────

def _get_client_info(request: Request) -> tuple[str, str]:
    """Extract client IP and user agent from request."""
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    return ip, ua


def _create_jwt(username: str, role: str, realm: str = "") -> str:
    """Create a JWT token - intentionally allows algorithm manipulation."""
    payload = {
        "sub": username,
        "role": role,
        "realm": realm,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _verify_jwt(token: str) -> dict | None:
    """Verify JWT - VULNERABLE: accepts 'none' algorithm."""
    try:
        # Try with the configured algorithm first
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM, "none"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        # Try decoding with 'none' algorithm (vulnerability!)
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception:
            return None


def _get_current_user(request: Request) -> dict | None:
    """Extract user from JWT or session cookie."""
    # Check Authorization header
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token = auth[7:]
        claims = _verify_jwt(token)
        if claims:
            username = claims.get("sub", "")
            return USERS_DB.get(username)

    # Check session cookie
    session_id = request.cookies.get("portal_session")
    if session_id and session_id in SESSIONS:
        session = SESSIONS[session_id]
        return USERS_DB.get(session.get("username"))

    return None


def _try_ldap_auth(username: str, password: str, domain: str = "") -> dict | None:
    """Attempt LDAP bind against GOAD domain controllers.

    Falls back gracefully if GOAD is unreachable.
    """
    try:
        import ldap3
        from ldap3 import Server, Connection, SIMPLE

        target_servers = LDAP_SERVERS
        if domain:
            target_servers = [s for s in LDAP_SERVERS if domain in s["domain"]] or LDAP_SERVERS

        for srv_info in target_servers:
            try:
                server = Server(srv_info["host"], port=389, get_info=ldap3.NONE, connect_timeout=2)
                # VULNERABLE: user input directly in bind DN (LDAP injection possible)
                bind_dn = f"{username}@{srv_info['domain']}"
                conn = Connection(server, user=bind_dn, password=password, authentication=SIMPLE,
                                  auto_bind=True, raise_exceptions=True, receive_timeout=3)
                conn.unbind()
                return {
                    "username": username,
                    "realm": srv_info["domain"],
                    "auth_method": "ldap",
                    "dc": srv_info["name"],
                }
            except Exception:
                continue

    except ImportError:
        logger.debug("ldap3 not installed, skipping LDAP auth")
    except Exception as e:
        logger.debug(f"LDAP auth failed: {e}")

    return None


def _try_mssql_query(server_name: str, query: str) -> list[dict] | None:
    """Execute a query against GOAD MSSQL - returns rows or None on failure."""
    srv = MSSQL_SERVERS.get(server_name)
    if not srv:
        return None
    try:
        conn = pymssql.connect(
            server=srv["host"], port=srv["port"],
            user="sa", password="password123!",
            database=srv["db"], login_timeout=3, timeout=2,
        )
        cursor = conn.cursor(as_dict=True)
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return rows
    except Exception as e:
        logger.debug(f"MSSQL query to {server_name} failed: {e}")
        return None


# ── Router ─────────────────────────────────────────────────────────
router = APIRouter(prefix="/portal", tags=["Vulnerable Portal"])


# ── Portal UI ──────────────────────────────────────────────────────
@router.get("/", response_class=HTMLResponse)
async def portal_index(request: Request):
    """Serve the main portal page."""
    html_file = STATIC_DIR / "portal.html"
    if not html_file.exists():
        return HTMLResponse("<h1>Portal</h1><p>portal.html not found. Deploy the portal UI.</p>")

    html = html_file.read_text(encoding="utf-8")

    # Inject APM config for RUM
    apm_ep = os.getenv("OCI_APM_ENDPOINT", "")
    apm_pub = os.getenv("OCI_APM_PUBLIC_DATAKEY", "")
    if apm_ep and apm_pub:
        html = html.replace("__APM_ENDPOINT__", apm_ep)
        html = html.replace("__APM_PUBLIC_KEY__", apm_pub)

    return html


@router.get("/health")
async def portal_health():
    """Portal health check with system info exposure (A05: Security Misconfiguration)."""
    # VULN: Exposes internal system details
    return {
        "status": "healthy",
        "version": "1.0.0-beta",
        "python_version": os.popen("python3 --version").read().strip(),
        "hostname": os.popen("hostname").read().strip(),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "debug_mode": True,
        "users_count": len(USERS_DB),
        "active_sessions": len(SESSIONS),
        "goad_servers": LDAP_SERVERS,
        "mssql_servers": MSSQL_SERVERS,
        "jwt_algorithm": JWT_ALGORITHM,
    }


# ═══════════════════════════════════════════════════════════════════
# A07: AUTHENTICATION VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/auth/login")
async def login(request: Request):
    """Login endpoint with multiple authentication vulnerabilities.

    Vulnerabilities:
        - No rate limiting (brute force, A07)
        - MD5 password hashing (A02: Cryptographic Failures)
        - LDAP injection when domain is specified (A03: Injection)
        - Default credentials: admin/admin (A07)
        - Verbose error messages distinguish valid/invalid usernames (A07)
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "").strip()
    domain = body.get("domain", "")

    # Track brute force attempts
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())
    recent = [t for t in LOGIN_ATTEMPTS[ip] if t > time.time() - 60]
    LOGIN_ATTEMPTS[ip] = recent

    if len(recent) > 10:
        with security_span("brute_force", severity="high", source_ip=ip,
                           username=username, user_agent=ua,
                           extra_attrs={"security.login.attempts_per_minute": len(recent)}):
            detection_event("brute_force", severity="high",
                            description=f"Brute force detected: {len(recent)} attempts/min from {ip}",
                            source_ip=ip, username=username)

    # Try LDAP auth against GOAD first
    if domain:
        # VULN A03: LDAP Injection - domain passed directly to bind DN
        ldap_special = any(c in username for c in ["*", "(", ")", "\\", "/", "\x00"])
        if ldap_special:
            with security_span("ldap_injection", severity="critical", payload=username,
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}"):
                return JSONResponse({
                    "status": "error",
                    "message": f"LDAP Error: Invalid DN syntax near '{username}'",
                    "flag": "FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}",
                    "hint": "LDAP injection detected! The username is passed directly to the bind DN."
                }, status_code=400)

        ldap_result = _try_ldap_auth(username, password, domain)
        if ldap_result:
            # Create session for LDAP user
            session_id = secrets.token_hex(16)
            SESSIONS[session_id] = {
                "username": username,
                "role": "user",
                "realm": ldap_result["realm"],
                "auth_method": "ldap",
                "created_at": time.time(),
            }
            token = _create_jwt(username, "user", ldap_result["realm"])
            resp = JSONResponse({
                "status": "success",
                "token": token,
                "user": {"username": username, "realm": ldap_result["realm"], "auth_method": "ldap"},
            })
            resp.set_cookie("portal_session", session_id, httponly=False)  # VULN: not httponly
            return resp

    # Local auth fallback
    user = USERS_DB.get(username)
    if not user:
        # VULN A07: Username enumeration
        return JSONResponse({
            "status": "error",
            "message": f"User '{username}' not found in any realm",  # Reveals valid usernames
        }, status_code=401)

    # VULN A02: MD5 password comparison
    if hashlib.md5(password.encode()).hexdigest() != user["password_hash"]:
        return JSONResponse({
            "status": "error",
            "message": "Invalid password for user " + username,  # Confirms user exists
        }, status_code=401)

    # Create session
    session_id = secrets.token_hex(16)
    SESSIONS[session_id] = {
        "username": username,
        "role": user["role"],
        "realm": user.get("realm", ""),
        "auth_method": "local",
        "created_at": time.time(),
    }
    token = _create_jwt(username, user["role"], user.get("realm", ""))
    resp = JSONResponse({
        "status": "success",
        "token": token,
        "user": {
            "username": user["username"],
            "role": user["role"],
            "full_name": user["full_name"],
            "title": user["title"],
        },
    })
    resp.set_cookie("portal_session", session_id, httponly=False, samesite="none")
    return resp


@router.post("/api/auth/register")
async def register(request: Request):
    """User registration with mass assignment vulnerability.

    VULN A04: Mass Assignment - user can set their own role to 'admin'.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    username = body.get("username", "")
    password = body.get("password", "")

    if not username or not password:
        return JSONResponse({"status": "error", "message": "Username and password required"}, status_code=400)

    if username in USERS_DB:
        return JSONResponse({"status": "error", "message": "Username already exists"}, status_code=409)

    # VULN A04: Mass Assignment - all body fields accepted, including 'role'
    new_user = {
        "id": max(u["id"] for u in USERS_DB.values()) + 1,
        "username": username,
        "password_hash": hashlib.md5(password.encode()).hexdigest(),
        "email": body.get("email", f"{username}@portal.local"),
        "role": body.get("role", "user"),  # VULN: user can set role!
        "realm": body.get("realm", "portal"),
        "full_name": body.get("full_name", username),
        "title": body.get("title", "Commoner"),
    }

    if new_user["role"] != "user":
        with security_span("mass_assignment", severity="critical", payload=json.dumps(body),
                           source_ip=ip, user_agent=ua, username=username,
                           flag="FLAG{M455_4551GNM3N7_PR1V35C}"):
            pass

    USERS_DB[username] = new_user
    return JSONResponse({"status": "success", "user": {k: v for k, v in new_user.items() if k != "password_hash"}})


@router.get("/api/auth/session-fixation")
async def session_fixation(request: Request, session_id: str = Query(None)):
    """Session fixation vulnerability.

    VULN A07: Accepts attacker-controlled session IDs.
    """
    ip, ua = _get_client_info(request)

    if session_id:
        # VULN: Attacker can pre-set a session ID, then trick victim into using it
        with security_span("auth_bypass", severity="high", payload=session_id,
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{S3SS10N_F1X4T10N_4TT4CK}",
                           extra_attrs={"security.session.fixated_id": session_id}):
            SESSIONS[session_id] = {"username": "guest", "role": "user", "created_at": time.time()}
            resp = JSONResponse({
                "status": "success",
                "message": "Session established with provided ID",
                "flag": "FLAG{S3SS10N_F1X4T10N_4TT4CK}",
                "session_id": session_id,
            })
            resp.set_cookie("portal_session", session_id)
            return resp

    return JSONResponse({"status": "info", "message": "Provide ?session_id= to demonstrate session fixation"})


# ═══════════════════════════════════════════════════════════════════
# A01: BROKEN ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/users/{user_id}")
async def get_user_profile(user_id: int, request: Request):
    """IDOR - Access any user's profile by ID.

    VULN A01: No authorization check on user_id.
    """
    ip, ua = _get_client_info(request)

    for user in USERS_DB.values():
        if user["id"] == user_id:
            # Check if accessing another user's data
            current = _get_current_user(request)
            if current and current["id"] != user_id:
                with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                                   username=current.get("username", "anonymous"),
                                   flag="FLAG{1D0R_PR0F1L3_L34K}",
                                   extra_attrs={"security.idor.target_user_id": user_id}):
                    pass
            return {
                "status": "success",
                "profile": {k: v for k, v in user.items() if k != "password_hash"},
            }

    return JSONResponse({"status": "error", "message": "User not found"}, status_code=404)


@router.get("/api/users")
async def list_all_users(request: Request):
    """List all users - exposes sensitive data.

    VULN A01: No access control, leaks password hashes and emails.
    """
    ip, ua = _get_client_info(request)
    include_hashes = request.query_params.get("debug", "") == "true"

    users_list = []
    for u in USERS_DB.values():
        entry = {"id": u["id"], "username": u["username"], "email": u["email"],
                 "role": u["role"], "full_name": u["full_name"]}
        if include_hashes:
            # VULN A02: Leaks MD5 password hashes in debug mode
            entry["password_hash"] = u["password_hash"]
            entry["hash_algorithm"] = "md5"
        users_list.append(entry)

    if include_hashes:
        with security_span("credential_leak", severity="critical", source_ip=ip, user_agent=ua,
                           flag="FLAG{CR3D3NT14L_DUMP_MD5}",
                           extra_attrs={"security.leak.type": "password_hashes", "security.leak.count": len(users_list)}):
            pass

    return {"status": "success", "users": users_list, "total": len(users_list)}


@router.get("/api/admin/panel")
async def admin_panel(request: Request):
    """Admin panel with privilege escalation via JWT manipulation.

    VULN A01: JWT role claim can be changed; accepts 'none' algorithm.
    """
    ip, ua = _get_client_info(request)
    user = _get_current_user(request)

    if not user:
        return JSONResponse({"status": "error", "message": "Authentication required",
                             "hint": "Use Bearer token with role='admin' or 'superadmin'"}, status_code=401)

    if user.get("role") not in ("admin", "superadmin"):
        # Check if the JWT was manipulated
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            try:
                # Decode without verification to inspect
                claims = jwt.decode(auth[7:], options={"verify_signature": False})
                if claims.get("role") in ("admin", "superadmin"):
                    with security_span("jwt_manipulation", severity="critical",
                                       payload=auth[7:], source_ip=ip, user_agent=ua,
                                       username=claims.get("sub", ""),
                                       flag="FLAG{JW7_N0N3_4LG0_BYPA55}",
                                       extra_attrs={"security.jwt.algorithm": claims.get("alg", "none"),
                                                    "security.jwt.claimed_role": claims.get("role")}):
                        pass
            except Exception:
                pass

        return JSONResponse({"status": "error", "message": "Insufficient privileges. Admin role required.",
                             "your_role": user.get("role", "unknown"),
                             "hint": "Try modifying the JWT token's 'role' claim or using algorithm='none'"}, status_code=403)

    return {
        "status": "success",
        "panel": "admin",
        "capabilities": ["user_management", "system_config", "log_viewer", "backup_restore"],
        "system_info": {
            "total_users": len(USERS_DB),
            "active_sessions": len(SESSIONS),
            "db_servers": list(MSSQL_SERVERS.keys()),
            "ldap_servers": [s["name"] for s in LDAP_SERVERS],
        },
    }


# ═══════════════════════════════════════════════════════════════════
# A03: INJECTION VULNERABILITIES
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/treasury/search")
async def treasury_search(request: Request, q: str = "", house: str = ""):
    """SQL Injection in treasury search - queries GOAD MSSQL when available.

    VULN A03: User input concatenated directly into SQL query.
    """
    ip, ua = _get_client_info(request)

    # Detect SQLi patterns
    sqli_patterns = ["union", "select", "insert", "update", "delete", "drop", "exec",
                     "--", "/*", "';", "' or", "1=1", "sleep(", "waitfor"]
    is_sqli = any(p in q.lower() for p in sqli_patterns)

    if is_sqli:
        with security_span("sqli", severity="critical", payload=q, source_ip=ip, user_agent=ua,
                           flag="FLAG{7R345URY_SQL1_BR34CH}",
                           extra_attrs={
                               "db.system": "mssql",
                               "db.statement": f"SELECT * FROM treasury WHERE description LIKE '%{q}%'",
                               "security.sqli.pattern_matched": True,
                           }):
            # Try real GOAD MSSQL
            raw_query = f"SELECT * FROM master.dbo.sysobjects WHERE name LIKE '%{q}%'"
            real_result = _try_mssql_query("castelblack", raw_query)
            if real_result is not None:
                return {
                    "status": "success",
                    "source": "goad_mssql",
                    "query": raw_query,
                    "data": real_result,
                    "flag": "FLAG{7R345URY_SQL1_BR34CH}",
                }

            # Fallback simulation
            return {
                "status": "success",
                "source": "simulated",
                "query_executed": f"SELECT * FROM treasury WHERE description LIKE '%{q}%'",
                "data": [
                    {"id": 9999, "description": "UNION result", "secret": "FLAG{7R345URY_SQL1_BR34CH}"},
                    {"id": 9998, "description": "sa_password: WinterIsComing2024!", "type": "credential_dump"},
                ],
                "flag": "FLAG{7R345URY_SQL1_BR34CH}",
            }

    # Normal search
    results = [t for t in TREASURY_DB
               if q.lower() in t.get("description", "").lower()
               or q.lower() in t.get("house", "").lower()]
    if house:
        results = [t for t in results if t.get("house", "").lower() == house.lower()]

    return {"status": "success", "data": results, "total": len(results)}


@router.get("/api/treasury/{record_id}")
async def get_treasury_record(record_id: int, request: Request):
    """IDOR on treasury records.

    VULN A01: No authorization check - any user can access any record.
    """
    ip, ua = _get_client_info(request)

    for record in TREASURY_DB:
        if record["id"] == record_id:
            if "secret" in record:
                with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                                   flag=record["secret"],
                                   extra_attrs={"security.idor.resource": "treasury", "security.idor.record_id": record_id}):
                    pass
            return {"status": "success", "data": record}

    return JSONResponse({"status": "error", "message": "Record not found"}, status_code=404)


@router.get("/api/command/exec")
async def command_exec(request: Request, cmd: str = "id"):
    """Command injection via diagnostic endpoint.

    VULN A03: Shell command injection - input passed to subprocess.
    """
    ip, ua = _get_client_info(request)

    # Detect command injection
    dangerous_chars = [";", "|", "&", "`", "$", "\n", "&&", "||"]
    dangerous_cmds = ["whoami", "id", "cat", "ls", "wget", "curl", "nc", "ncat",
                      "python", "perl", "ruby", "bash", "sh", "powershell"]
    is_injection = (any(c in cmd for c in dangerous_chars) or
                    any(c in cmd.lower() for c in dangerous_cmds))

    if is_injection:
        with security_span("rce", severity="critical", payload=cmd, source_ip=ip, user_agent=ua,
                           flag="FLAG{C0MM4ND_1NJ3CT10N_RCE}",
                           extra_attrs={"security.rce.command": cmd}):
            # Simulate command output (don't actually execute)
            simulated_outputs = {
                "whoami": "observability",
                "id": "uid=1001(observability) gid=1001(observability) groups=1001(observability)",
                "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nobservability:x:1001:1001::/opt/observability:/bin/false",
                "uname -a": "Linux seven-kingdoms 5.15.0-1050-oracle #56-Ubuntu SMP x86_64 GNU/Linux",
            }
            # Find matching simulated output
            output = "Command executed (simulated)"
            for key, val in simulated_outputs.items():
                if key in cmd.lower():
                    output = val
                    break

            return {
                "status": "success",
                "command": cmd,
                "output": output,
                "flag": "FLAG{C0MM4ND_1NJ3CT10N_RCE}",
                "warning": "Command injection detected!",
            }

    # Safe commands only
    allowed = ["uptime", "date", "df -h", "free -m"]
    if cmd in allowed:
        return {"status": "success", "command": cmd, "output": f"Simulated output for: {cmd}"}

    return JSONResponse({"status": "error", "message": f"Command '{cmd}' not in allowed list: {allowed}"}, status_code=403)


@router.get("/api/template/render")
async def template_render(request: Request, tpl: str = "Hello, {{name}}!", name: str = "traveler"):
    """Server-Side Template Injection.

    VULN A03: User input evaluated in template expression.
    """
    ip, ua = _get_client_info(request)

    # Detect SSTI patterns
    ssti_patterns = ["{{", "}}", "{%", "__class__", "__mro__", "__subclasses__",
                     "__import__", "config", "self", "request"]
    is_ssti = any(p in tpl for p in ssti_patterns) or any(p in name for p in ssti_patterns)

    if is_ssti:
        with security_span("ssti", severity="critical", payload=f"tpl={tpl}&name={name}",
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}"):
            # Simulate template evaluation
            rendered = tpl.replace("{{name}}", name)
            if "{{7*7}}" in tpl:
                rendered = rendered.replace("{{7*7}}", "49")
            if "__class__" in name:
                rendered = "<class 'str'> → __subclasses__ → FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}"

            return {
                "status": "success",
                "rendered": rendered,
                "flag": "FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}",
                "template_engine": "jinja2 (simulated)",
            }

    rendered = tpl.replace("{{name}}", name)
    return {"status": "success", "rendered": rendered}


@router.get("/api/ldap/lookup")
async def ldap_lookup(request: Request, username: str = "", domain: str = "sevenkingdoms.local"):
    """LDAP injection via user lookup.

    VULN A03: Username passed directly into LDAP filter.
    """
    ip, ua = _get_client_info(request)

    # The LDAP filter would be: (&(sAMAccountName={username})(objectClass=user))
    ldap_filter = f"(&(sAMAccountName={username})(objectClass=user))"

    # Detect LDAP injection
    ldap_special = any(c in username for c in ["*", "(", ")", "\\", "|", "&", "\x00"])

    if ldap_special:
        with security_span("ldap_injection", severity="critical",
                           payload=f"filter={ldap_filter}", source_ip=ip, user_agent=ua,
                           flag="FLAG{LD4P_F1LT3R_1NJ3CT10N}",
                           extra_attrs={
                               "security.ldap.filter": ldap_filter,
                               "security.ldap.domain": domain,
                           }):
            # Simulate LDAP injection results
            if "*" in username:
                return {
                    "status": "success",
                    "filter_used": ldap_filter,
                    "results": [
                        {"dn": "CN=Administrator,CN=Users,DC=sevenkingdoms,DC=local", "sAMAccountName": "Administrator"},
                        {"dn": "CN=krbtgt,CN=Users,DC=sevenkingdoms,DC=local", "sAMAccountName": "krbtgt"},
                        {"dn": "CN=arya.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local", "sAMAccountName": "arya.stark"},
                    ],
                    "flag": "FLAG{LD4P_F1LT3R_1NJ3CT10N}",
                    "hint": "Wildcard * enumerated all domain users!",
                }

            return {
                "status": "success",
                "filter_used": ldap_filter,
                "results": [{"dn": "CN=injected,DC=local", "note": "LDAP filter was manipulated"}],
                "flag": "FLAG{LD4P_F1LT3R_1NJ3CT10N}",
            }

    # Normal lookup
    user = USERS_DB.get(username)
    if user:
        return {"status": "success", "results": [{"username": user["username"], "email": user["email"],
                                                    "realm": user.get("realm", "")}]}
    return {"status": "success", "results": [], "message": f"No user found matching '{username}'"}


# ═══════════════════════════════════════════════════════════════════
# A10: SERVER-SIDE REQUEST FORGERY
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/avatar/fetch")
async def fetch_avatar(request: Request, url: str = ""):
    """SSRF via avatar URL fetch.

    VULN A10: Fetches arbitrary URLs server-side.
    """
    ip, ua = _get_client_info(request)

    if not url:
        return JSONResponse({"status": "error", "message": "Provide ?url= to fetch an avatar image"}, status_code=400)

    # Detect SSRF targets
    internal_patterns = ["169.254.169.254", "metadata.google", "10.0.", "192.168.",
                         "172.16.", "127.0.0.1", "localhost", "0.0.0.0"]
    is_internal = any(p in url for p in internal_patterns)

    if is_internal:
        with security_span("ssrf", severity="critical", payload=url, source_ip=ip, user_agent=ua,
                           flag="FLAG{55RF_1NT3RN4L_4CC355}",
                           extra_attrs={
                               "http.url": url,
                               "security.ssrf.target_internal": True,
                               "security.ssrf.target_type": "cloud_metadata" if "169.254" in url else "internal_network",
                           }):
            # Try real fetch (for GOAD integration)
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.get(url)
                    return {
                        "status": "success",
                        "url": url,
                        "response_code": resp.status_code,
                        "data": resp.text[:1000],
                        "flag": "FLAG{55RF_1NT3RN4L_4CC355}",
                    }
            except Exception:
                # Simulate internal response
                if "169.254.169.254" in url:
                    return {
                        "status": "success",
                        "url": url,
                        "data": '{"instance_id": "ocid1.instance.oc1.eu-frankfurt-1.xxx", "region": "eu-frankfurt-1"}',
                        "flag": "FLAG{55RF_1NT3RN4L_4CC355}",
                        "note": "Cloud metadata accessed!",
                    }
                return {
                    "status": "success",
                    "url": url,
                    "data": "Internal host responded (simulated)",
                    "flag": "FLAG{55RF_1NT3RN4L_4CC355}",
                }

    # External URL - fetch normally
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            return {"status": "success", "url": url, "content_type": resp.headers.get("content-type", ""),
                    "size": len(resp.content)}
    except Exception as e:
        return JSONResponse({"status": "error", "message": f"Failed to fetch: {str(e)}"}, status_code=502)


@router.post("/api/webhook/send")
async def send_webhook(request: Request):
    """SSRF via webhook functionality.

    VULN A10: Server makes requests to attacker-controlled URLs.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    webhook_url = body.get("url", "")
    payload_data = body.get("data", {})

    if not webhook_url:
        return JSONResponse({"status": "error", "message": "Webhook URL required"}, status_code=400)

    internal_patterns = ["10.0.", "192.168.", "172.16.", "127.0.0.1", "localhost"]
    is_internal = any(p in webhook_url for p in internal_patterns)

    with security_span("ssrf", severity="high" if is_internal else "medium",
                       payload=webhook_url, source_ip=ip, user_agent=ua,
                       extra_attrs={
                           "http.url": webhook_url,
                           "http.method": "POST",
                           "security.ssrf.target_internal": is_internal,
                       }):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(webhook_url, json=payload_data)
                return {"status": "success", "response_code": resp.status_code, "url": webhook_url}
        except Exception as e:
            if is_internal:
                return {"status": "success", "message": "Internal endpoint contacted (simulated)", "url": webhook_url,
                        "flag": "FLAG{W3BH00K_55RF_1NT3RN4L}"}
            return JSONResponse({"status": "error", "message": f"Webhook failed: {str(e)}"}, status_code=502)


# ═══════════════════════════════════════════════════════════════════
# A01: PATH TRAVERSAL / FILE ACCESS
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/files/download")
async def download_file(request: Request, path: str = "readme.txt"):
    """Path traversal in file download.

    VULN A01: Path traversal allows reading arbitrary files.
    """
    ip, ua = _get_client_info(request)

    # Detect path traversal
    if ".." in path or path.startswith("/"):
        with security_span("path_traversal", severity="critical", payload=path,
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{P4TH_TR4V3RS4L_LFI}",
                           extra_attrs={"security.file.path": path}):
            # Simulate file content
            if "/etc/passwd" in path:
                return {"status": "success", "path": path,
                        "content": "root:x:0:0:root:/root:/bin/bash\nobservability:x:1001:1001::/opt/observability:/bin/false\n",
                        "flag": "FLAG{P4TH_TR4V3RS4L_LFI}"}
            if "/etc/shadow" in path:
                return {"status": "success", "path": path,
                        "content": "root:$6$salted$hashedpassword:19000:0:99999:7:::\n",
                        "flag": "FLAG{P4TH_TR4V3RS4L_LFI}"}
            if ".env" in path or "config" in path.lower():
                return {"status": "success", "path": path,
                        "content": "DB_PASSWORD=WinterIsComing2024!\nJWT_SECRET=seven-kingdoms-secret-key-2024\n",
                        "flag": "FLAG{P4TH_TR4V3RS4L_LFI}"}
            return {"status": "success", "path": path, "content": "(file content simulated)",
                    "flag": "FLAG{P4TH_TR4V3RS4L_LFI}"}

    # Safe file listing
    safe_files = {
        "readme.txt": "Welcome to the Seven Kingdoms Portal. This is a demo application.",
        "changelog.md": "## v1.0.0\n- Initial release\n- Added treasury module\n- Added raven messaging",
    }
    if path in safe_files:
        return {"status": "success", "path": path, "content": safe_files[path]}
    return JSONResponse({"status": "error", "message": f"File '{path}' not found"}, status_code=404)


@router.get("/api/files/list")
async def list_files(request: Request, dir: str = "."):
    """Directory listing with path traversal.

    VULN A05: Directory listing enabled, traversal not blocked.
    """
    ip, ua = _get_client_info(request)

    if ".." in dir or dir.startswith("/"):
        with security_span("path_traversal", severity="high", payload=dir,
                           source_ip=ip, user_agent=ua,
                           extra_attrs={"security.file.directory": dir}):
            return {
                "status": "success",
                "directory": dir,
                "files": [
                    {"name": ".env.local", "size": 2048, "type": "file"},
                    {"name": "config.json", "size": 512, "type": "file"},
                    {"name": "keys/", "size": 0, "type": "directory"},
                    {"name": "backup.sql.gz", "size": 1048576, "type": "file"},
                ],
                "warning": "Directory traversal - listing sensitive directory contents",
            }

    return {
        "status": "success",
        "directory": dir,
        "files": [
            {"name": "readme.txt", "size": 128, "type": "file"},
            {"name": "changelog.md", "size": 256, "type": "file"},
            {"name": "uploads/", "size": 0, "type": "directory"},
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# RAVEN MESSAGES (with XSS and IDOR)
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/messages")
async def list_messages(request: Request, user: str = ""):
    """List messages - IDOR allows reading anyone's messages.

    VULN A01: No authorization, can read any user's messages.
    """
    ip, ua = _get_client_info(request)

    if user:
        msgs = [m for m in MESSAGES_DB if m["to"] == user or m["from"] == user]
    else:
        # VULN: Returns ALL messages without auth
        msgs = MESSAGES_DB

    # Check if accessing admin messages
    admin_msgs = [m for m in msgs if "admin" in m.get("to", "") or "admin" in m.get("from", "")]
    if admin_msgs:
        with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                           extra_attrs={"security.idor.resource": "messages", "security.idor.count": len(admin_msgs)}):
            pass

    return {"status": "success", "messages": msgs, "total": len(msgs)}


@router.get("/api/messages/{msg_id}")
async def get_message(msg_id: int, request: Request):
    """Get message by ID - IDOR.

    VULN A01: No auth check on message access.
    """
    for msg in MESSAGES_DB:
        if msg["id"] == msg_id:
            return {"status": "success", "message": msg}
    return JSONResponse({"status": "error", "message": "Message not found"}, status_code=404)


@router.post("/api/messages/send")
async def send_message(request: Request):
    """Send a message with stored XSS.

    VULN A03: Message body not sanitized - stored XSS.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    msg_body = body.get("body", "")
    subject = body.get("subject", "")

    # Detect XSS patterns
    xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "onfocus=",
                    "<img", "<svg", "<iframe", "alert(", "document.cookie"]
    is_xss = any(p in msg_body.lower() for p in xss_patterns) or any(p in subject.lower() for p in xss_patterns)

    new_msg = {
        "id": max(m["id"] for m in MESSAGES_DB) + 1,
        "from": body.get("from", "anonymous"),
        "to": body.get("to", "admin"),
        "subject": subject,  # VULN: Not sanitized
        "body": msg_body,    # VULN: Not sanitized - stored XSS
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": False,
    }

    if is_xss:
        with security_span("xss", severity="high", payload=msg_body[:200], source_ip=ip, user_agent=ua,
                           flag="FLAG{570R3D_X55_R4V3N}",
                           extra_attrs={"security.xss.type": "stored", "security.xss.field": "message_body"}):
            new_msg["flag"] = "FLAG{570R3D_X55_R4V3N}"

    MESSAGES_DB.append(new_msg)
    return {"status": "success", "message_id": new_msg["id"],
            **({"flag": "FLAG{570R3D_X55_R4V3N}", "warning": "XSS payload stored!"} if is_xss else {})}


# ═══════════════════════════════════════════════════════════════════
# A02: CRYPTOGRAPHIC FAILURES
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/debug/crypto")
async def debug_crypto(request: Request):
    """Exposes cryptographic configuration.

    VULN A02: Reveals JWT secret, hashing algorithm, encryption keys.
    """
    ip, ua = _get_client_info(request)

    with security_span("credential_leak", severity="critical", source_ip=ip, user_agent=ua,
                       flag="FLAG{CRYPT0_F41LUR3_D3BUG}",
                       extra_attrs={"security.leak.type": "crypto_config"}):
        return {
            "status": "success",
            "crypto_config": {
                "jwt_secret": JWT_SECRET,
                "jwt_algorithm": JWT_ALGORITHM,
                "password_hash_algo": "MD5 (INSECURE)",
                "session_token_length": 32,
                "encryption_key": "AES-128-ECB-DEFAULT-KEY-INSECURE",
                "tls_version": "TLSv1.0 (DEPRECATED)",
            },
            "sample_jwt": _create_jwt("debug_user", "superadmin"),
            "flag": "FLAG{CRYPT0_F41LUR3_D3BUG}",
        }


@router.get("/api/debug/env")
async def debug_env(request: Request):
    """Exposes environment variables.

    VULN A05: Debug endpoint leaks sensitive environment config.
    """
    ip, ua = _get_client_info(request)

    with security_span("credential_leak", severity="critical", source_ip=ip, user_agent=ua,
                       flag="FLAG{3NV_L34K_D3BUG_M0D3}",
                       extra_attrs={"security.leak.type": "environment_variables"}):
        # Selectively expose env vars (simulated + real safe ones)
        safe_vars = {
            "ENVIRONMENT": os.getenv("ENVIRONMENT", "development"),
            "OCI_REGION": os.getenv("OCI_REGION", "eu-frankfurt-1"),
            "OCI_APM_ENDPOINT": os.getenv("OCI_APM_ENDPOINT", "(not set)"),
            "PORTAL_JWT_SECRET": JWT_SECRET,
            "DB_HOST": "castelblack.north.sevenkingdoms.local",
            "DB_PASSWORD": "WinterIsComing2024!",
            "LDAP_BIND_PASSWORD": "Passw0rd!",
            "SSH_KEY_PATH": "/opt/keys/id_rsa",
            "API_KEYS": {"caldera": "ADMIN123", "splunk_hec": "mock-hec-token"},
        }
        return {"status": "success", "environment": safe_vars, "flag": "FLAG{3NV_L34K_D3BUG_M0D3}"}


# ═══════════════════════════════════════════════════════════════════
# A08: SOFTWARE AND DATA INTEGRITY FAILURES
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/import/profile")
async def import_profile_data(request: Request, data: str = Query(...)):
    """Insecure deserialization via pickle.

    VULN A08: Base64-encoded pickle data loaded without validation.
    """
    ip, ua = _get_client_info(request)

    try:
        decoded = base64.b64decode(data)
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid base64"}, status_code=400)

    # Detect dangerous pickle patterns
    dangerous_patterns = [b"__reduce__", b"os.system", b"subprocess", b"exec", b"eval",
                         b"FLAG_INJECTED", b"__import__"]
    is_dangerous = any(p in decoded for p in dangerous_patterns)

    if is_dangerous:
        with security_span("deserialization", severity="critical", payload=data[:100],
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{D3S3R14L1Z4T10N_RC3}",
                           extra_attrs={"security.deserialization.format": "python_pickle"}):
            return {
                "status": "success",
                "message": "Pickle payload executed (simulated)",
                "result": "Remote code execution achieved!",
                "flag": "FLAG{D3S3R14L1Z4T10N_RC3}",
            }

    return {"status": "success", "message": "Profile imported", "size": len(decoded)}


@router.post("/api/import/json")
async def import_json_unsafe(request: Request):
    """JSON import with prototype pollution simulation.

    VULN A08: Accepts __proto__ and constructor properties.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    # Check for prototype pollution patterns
    def check_proto(obj, path=""):
        if isinstance(obj, dict):
            for key in obj:
                if key in ("__proto__", "constructor", "__class__"):
                    return True, f"{path}.{key}"
                found, p = check_proto(obj[key], f"{path}.{key}")
                if found:
                    return True, p
        return False, ""

    is_polluted, pollution_path = check_proto(body)
    if is_polluted:
        with security_span("deserialization", severity="high", payload=json.dumps(body)[:200],
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{PR0T0_P0LLUT10N}",
                           extra_attrs={"security.pollution.path": pollution_path}):
            return {
                "status": "success",
                "message": "Prototype pollution detected and applied!",
                "pollution_path": pollution_path,
                "flag": "FLAG{PR0T0_P0LLUT10N}",
            }

    return {"status": "success", "message": "JSON imported", "keys": list(body.keys())}


# ═══════════════════════════════════════════════════════════════════
# A09: SECURITY LOGGING AND MONITORING FAILURES
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/silent/transfer")
async def silent_transfer(request: Request, from_account: str = "", to_account: str = "", amount: float = 0):
    """Financial transfer that intentionally doesn't log properly.

    VULN A09: Critical action with insufficient logging.
    """
    ip, ua = _get_client_info(request)

    # INTENTIONALLY: No security logging, no OTEL span, no metric
    # This is a detection gap - security team should notice missing logs for transfers
    if amount > 10000:
        # Only log extremely large transfers
        logger.warning(f"Large transfer: {amount} from {from_account} to {to_account}")

    return {
        "status": "success",
        "transaction_id": str(uuid.uuid4()),
        "from": from_account,
        "to": to_account,
        "amount": amount,
        "note": "Transfer processed. No additional logging performed (A09 vulnerability).",
    }


@router.get("/api/log-injection")
async def log_injection(request: Request, msg: str = ""):
    """Log injection via user-controlled log message.

    VULN A09: User input written directly to log without sanitization.
    """
    ip, ua = _get_client_info(request)

    # Detect log injection patterns
    log_patterns = ["\n", "\r", "%0a", "%0d", "\\n", "\\r"]
    is_injection = any(p in msg for p in log_patterns)

    if is_injection:
        with security_span("log_injection", severity="medium", payload=msg[:200],
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{L0G_1NJ3CT10N_F0RG3RY}",
                           extra_attrs={"security.log.injected_content": msg[:200]}):
            pass

    # VULN: Unsanitized user input in log
    logger.info(f"User activity: {msg}")

    return {
        "status": "success",
        "logged": True,
        "message": msg,
        **({"flag": "FLAG{L0G_1NJ3CT10N_F0RG3RY}", "warning": "Log injection detected!"} if is_injection else {}),
    }


# ═══════════════════════════════════════════════════════════════════
# A04: INSECURE DESIGN
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/password-reset")
async def password_reset(request: Request, username: str = ""):
    """Predictable password reset token.

    VULN A04: Reset token derived from username + timestamp (predictable).
    """
    ip, ua = _get_client_info(request)

    if not username:
        return JSONResponse({"status": "error", "message": "Username required"}, status_code=400)

    # VULN: Predictable token generation
    timestamp = int(time.time())
    reset_token = hashlib.md5(f"{username}:{timestamp}".encode()).hexdigest()

    with security_span("auth_bypass", severity="medium", source_ip=ip, user_agent=ua,
                       username=username,
                       flag="FLAG{PR3D1CT4BL3_R3S3T}",
                       extra_attrs={
                           "security.reset.token_algorithm": "md5(username:timestamp)",
                           "security.reset.timestamp_used": timestamp,
                       }):
        pass

    return {
        "status": "success",
        "message": f"Reset link sent to {username}'s email",
        "reset_token": reset_token,
        "expires_at": timestamp + 3600,
        "flag": "FLAG{PR3D1CT4BL3_R3S3T}",
        "hint": f"Token = MD5('{username}:{timestamp}'). Can you predict future tokens?",
    }


@router.post("/api/treasury/transfer")
async def treasury_transfer(request: Request):
    """Business logic vulnerability - negative amounts.

    VULN A04: No validation on negative transfer amounts.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    amount = body.get("amount", 0)
    from_house = body.get("from", "")
    to_house = body.get("to", "")

    if amount < 0:
        with security_span("auth_bypass", severity="high",
                           payload=json.dumps(body), source_ip=ip, user_agent=ua,
                           flag="FLAG{N3G4T1V3_TR4NSF3R_L0G1C}",
                           extra_attrs={"security.business_logic.negative_amount": amount}):
            return {
                "status": "success",
                "message": f"Transferred {amount} gold from {from_house} to {to_house}",
                "note": "Negative amount effectively REVERSED the transfer direction!",
                "flag": "FLAG{N3G4T1V3_TR4NSF3R_L0G1C}",
            }

    return {
        "status": "success",
        "message": f"Transferred {amount} gold from {from_house} to {to_house}",
        "transaction_id": str(uuid.uuid4()),
    }


# ═══════════════════════════════════════════════════════════════════
# OPEN REDIRECT
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/redirect")
async def open_redirect(request: Request, url: str = "/portal/", next: str = ""):
    """Open redirect vulnerability.

    VULN A01: Redirects to any URL without validation.
    """
    ip, ua = _get_client_info(request)
    target = next or url

    # Detect external redirects
    is_external = target.startswith("http") and "sevenkingdoms" not in target

    if is_external:
        with security_span("open_redirect", severity="medium", payload=target,
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{0P3N_R3D1R3CT_PH1SH}",
                           extra_attrs={"security.redirect.target": target, "security.redirect.external": True}):
            pass

    return RedirectResponse(url=target, status_code=302)


# ═══════════════════════════════════════════════════════════════════
# GOAD INTEGRATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/goad/domains")
async def goad_domain_info(request: Request):
    """Information about connected GOAD Active Directory domains."""
    return {
        "status": "success",
        "domains": [
            {"name": "sevenkingdoms.local", "dc": "kingslanding (192.168.56.10)", "role": "Forest Root"},
            {"name": "north.sevenkingdoms.local", "dc": "winterfell (192.168.56.11)", "role": "Child Domain"},
            {"name": "essos.local", "dc": "meereen (192.168.56.12)", "role": "External Trust"},
        ],
        "servers": {
            "mssql": [
                {"name": "castelblack", "ip": "192.168.56.22", "port": 1433, "domain": "north.sevenkingdoms.local"},
                {"name": "braavos", "ip": "192.168.56.23", "port": 1433, "domain": "essos.local"},
            ],
        },
        "integration_status": "Check /portal/api/goad/connectivity for live status",
    }


@router.get("/api/goad/connectivity")
async def goad_connectivity(request: Request):
    """Test connectivity to GOAD infrastructure."""
    results = {}

    # Test LDAP
    for srv in LDAP_SERVERS:
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((srv["host"], 389))
            s.close()
            results[f"ldap_{srv['name']}"] = {"host": srv["host"], "port": 389,
                                               "status": "reachable" if result == 0 else "unreachable"}
        except Exception as e:
            results[f"ldap_{srv['name']}"] = {"host": srv["host"], "port": 389, "status": f"error: {str(e)}"}

    # Test MSSQL
    for name, srv in MSSQL_SERVERS.items():
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((srv["host"], srv["port"]))
            s.close()
            results[f"mssql_{name}"] = {"host": srv["host"], "port": srv["port"],
                                         "status": "reachable" if result == 0 else "unreachable"}
        except Exception as e:
            results[f"mssql_{name}"] = {"host": srv["host"], "port": srv["port"], "status": f"error: {str(e)}"}

    return {"status": "success", "connectivity": results}


@router.get("/api/goad/kerberoast")
async def goad_kerberoast_sim(request: Request, spn: str = "MSSQLSvc/castelblack.north.sevenkingdoms.local"):
    """Simulates Kerberoasting attack for detection.

    Generates spans that look like real Kerberoasting activity in OTEL/APM.
    """
    ip, ua = _get_client_info(request)

    with security_span("auth_bypass", severity="critical", payload=spn,
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{K3RB3R04ST_T1CK3T}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1558.003",
                           "security.attack.mitre_name": "Kerberoasting",
                           "security.kerberos.spn": spn,
                           "security.kerberos.ticket_type": "TGS",
                           "security.kerberos.encryption": "RC4_HMAC_MD5",
                       }) as span:
        return {
            "status": "success",
            "attack": "Kerberoasting (T1558.003)",
            "spn": spn,
            "ticket_hash": "$krb5tgs$23$*sqlsvc$NORTH.SEVENKINGDOMS.LOCAL$MSSQLSvc/castelblack*$" +
                          secrets.token_hex(32),
            "note": "This TGS ticket uses RC4 encryption (crackable). Run hashcat -m 13100.",
            "flag": "FLAG{K3RB3R04ST_T1CK3T}",
        }


@router.get("/api/goad/dcsync")
async def goad_dcsync_sim(request: Request, target: str = "Administrator"):
    """Simulates DCSync attack for detection.

    Generates spans mimicking DCSync (T1003.006) replication traffic.
    """
    ip, ua = _get_client_info(request)

    with security_span("credential_leak", severity="critical", payload=target,
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{DC5YNC_R3PL1C4T10N}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1003.006",
                           "security.attack.mitre_name": "DCSync",
                           "security.dcsync.target_user": target,
                           "security.dcsync.protocol": "MS-DRSR",
                           "security.dcsync.domain": "sevenkingdoms.local",
                       }) as span:
        return {
            "status": "success",
            "attack": "DCSync (T1003.006)",
            "target": target,
            "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:" + secrets.token_hex(16),
            "domain": "sevenkingdoms.local",
            "note": "Domain replication simulated. NTLM hash extracted.",
            "flag": "FLAG{DC5YNC_R3PL1C4T10N}",
        }


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY CATALOG & CTF SCOREBOARD
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/vulnerabilities")
async def vulnerability_catalog():
    """Returns the complete catalog of vulnerabilities and their flags."""
    return {
        "status": "success",
        "total_vulnerabilities": 25,
        "owasp_coverage": {
            "A01:2021-Broken Access Control": [
                {"id": "VULN-001", "name": "IDOR on User Profiles", "endpoint": "GET /portal/api/users/{id}", "severity": "high", "flag": "FLAG{1D0R_PR0F1L3_L34K}"},
                {"id": "VULN-002", "name": "IDOR on Treasury Records", "endpoint": "GET /portal/api/treasury/{id}", "severity": "high", "flag": "FLAG{7R345URY_4CC355}"},
                {"id": "VULN-003", "name": "IDOR on Messages", "endpoint": "GET /portal/api/messages", "severity": "high", "flag": "FLAG{R4V3N_1NT3RC3PT}"},
                {"id": "VULN-004", "name": "Path Traversal", "endpoint": "GET /portal/api/files/download", "severity": "critical", "flag": "FLAG{P4TH_TR4V3RS4L_LFI}"},
                {"id": "VULN-005", "name": "Open Redirect", "endpoint": "GET /portal/api/redirect", "severity": "medium", "flag": "FLAG{0P3N_R3D1R3CT_PH1SH}"},
            ],
            "A02:2021-Cryptographic Failures": [
                {"id": "VULN-006", "name": "MD5 Password Hashing", "endpoint": "GET /portal/api/users?debug=true", "severity": "critical", "flag": "FLAG{CR3D3NT14L_DUMP_MD5}"},
                {"id": "VULN-007", "name": "Crypto Config Leak", "endpoint": "GET /portal/api/debug/crypto", "severity": "critical", "flag": "FLAG{CRYPT0_F41LUR3_D3BUG}"},
            ],
            "A03:2021-Injection": [
                {"id": "VULN-008", "name": "SQL Injection (Treasury)", "endpoint": "GET /portal/api/treasury/search?q=", "severity": "critical", "flag": "FLAG{7R345URY_SQL1_BR34CH}"},
                {"id": "VULN-009", "name": "Command Injection", "endpoint": "GET /portal/api/command/exec?cmd=", "severity": "critical", "flag": "FLAG{C0MM4ND_1NJ3CT10N_RCE}"},
                {"id": "VULN-010", "name": "SSTI", "endpoint": "GET /portal/api/template/render", "severity": "critical", "flag": "FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}"},
                {"id": "VULN-011", "name": "LDAP Injection", "endpoint": "GET /portal/api/ldap/lookup", "severity": "critical", "flag": "FLAG{LD4P_F1LT3R_1NJ3CT10N}"},
                {"id": "VULN-012", "name": "Stored XSS", "endpoint": "POST /portal/api/messages/send", "severity": "high", "flag": "FLAG{570R3D_X55_R4V3N}"},
            ],
            "A04:2021-Insecure Design": [
                {"id": "VULN-013", "name": "Mass Assignment", "endpoint": "POST /portal/api/auth/register", "severity": "critical", "flag": "FLAG{M455_4551GNM3N7_PR1V35C}"},
                {"id": "VULN-014", "name": "Predictable Reset Token", "endpoint": "GET /portal/api/password-reset", "severity": "medium", "flag": "FLAG{PR3D1CT4BL3_R3S3T}"},
                {"id": "VULN-015", "name": "Negative Transfer", "endpoint": "POST /portal/api/treasury/transfer", "severity": "high", "flag": "FLAG{N3G4T1V3_TR4NSF3R_L0G1C}"},
            ],
            "A05:2021-Security Misconfiguration": [
                {"id": "VULN-016", "name": "Debug Endpoint", "endpoint": "GET /portal/api/debug/env", "severity": "critical", "flag": "FLAG{3NV_L34K_D3BUG_M0D3}"},
                {"id": "VULN-017", "name": "Health Info Leak", "endpoint": "GET /portal/health", "severity": "medium"},
            ],
            "A07:2021-Auth Failures": [
                {"id": "VULN-018", "name": "JWT Algorithm None", "endpoint": "GET /portal/api/admin/panel", "severity": "critical", "flag": "FLAG{JW7_N0N3_4LG0_BYPA55}"},
                {"id": "VULN-019", "name": "Session Fixation", "endpoint": "GET /portal/api/auth/session-fixation", "severity": "high", "flag": "FLAG{S3SS10N_F1X4T10N_4TT4CK}"},
                {"id": "VULN-020", "name": "Brute Force (No Rate Limit)", "endpoint": "POST /portal/api/auth/login", "severity": "medium"},
                {"id": "VULN-021", "name": "Default Creds: admin/admin", "endpoint": "POST /portal/api/auth/login", "severity": "high"},
                {"id": "VULN-022", "name": "LDAP Injection Login", "endpoint": "POST /portal/api/auth/login", "severity": "critical", "flag": "FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}"},
            ],
            "A08:2021-Integrity Failures": [
                {"id": "VULN-023", "name": "Pickle Deserialization", "endpoint": "POST /portal/api/import/profile", "severity": "critical", "flag": "FLAG{D3S3R14L1Z4T10N_RC3}"},
                {"id": "VULN-024", "name": "Prototype Pollution", "endpoint": "POST /portal/api/import/json", "severity": "high", "flag": "FLAG{PR0T0_P0LLUT10N}"},
            ],
            "A09:2021-Logging Failures": [
                {"id": "VULN-025", "name": "Silent Transfer (No Logging)", "endpoint": "GET /portal/api/silent/transfer", "severity": "high"},
                {"id": "VULN-026", "name": "Log Injection", "endpoint": "GET /portal/api/log-injection", "severity": "medium", "flag": "FLAG{L0G_1NJ3CT10N_F0RG3RY}"},
            ],
            "A10:2021-SSRF": [
                {"id": "VULN-027", "name": "Avatar SSRF", "endpoint": "GET /portal/api/avatar/fetch?url=", "severity": "critical", "flag": "FLAG{55RF_1NT3RN4L_4CC355}"},
                {"id": "VULN-028", "name": "Webhook SSRF", "endpoint": "POST /portal/api/webhook/send", "severity": "high", "flag": "FLAG{W3BH00K_55RF_1NT3RN4L}"},
            ],
            "GOAD Integration": [
                {"id": "VULN-029", "name": "Kerberoasting Simulation", "endpoint": "GET /portal/api/goad/kerberoast", "severity": "critical", "flag": "FLAG{K3RB3R04ST_T1CK3T}"},
                {"id": "VULN-030", "name": "DCSync Simulation", "endpoint": "GET /portal/api/goad/dcsync", "severity": "critical", "flag": "FLAG{DC5YNC_R3PL1C4T10N}"},
            ],
        },
    }


# ── Detection Rules API ──────────────────────────────────────────
@router.get("/api/detection-rules")
async def get_detection_rules(
    severity: str | None = None,
    mitre_tactic: str | None = None,
    owasp: str | None = None,
):
    """Return all detection rules, optionally filtered by severity, MITRE tactic, or OWASP category."""
    rules = DETECTION_RULES
    if severity:
        rules = [r for r in rules if r["severity"] == severity]
    if mitre_tactic:
        rules = [r for r in rules if r["mitre_tactic"] == mitre_tactic]
    if owasp:
        rules = [r for r in rules if owasp in r["owasp"]]
    return {
        "status": "success",
        "total": len(rules),
        "rules": rules,
        "query_examples": {
            "all_attacks": "SpanAttribute['security.attack.detected'] = 'true'",
            "critical_only": "SpanAttribute['security.attack.severity'] = 'critical'",
            "by_mitre": "SpanAttribute['security.attack.mitre_id'] = 'T1190'",
            "by_owasp": "SpanAttribute['security.attack.owasp'] like 'A03%'",
            "attack_chain": (
                "SpanAttribute['security.attack.detected'] = 'true' "
                "| stats distinctcount(security.attack.type) as types by security.source_ip "
                "| where types >= 3"
            ),
        },
    }
