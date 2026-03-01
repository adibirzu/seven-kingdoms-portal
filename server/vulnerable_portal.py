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
from .flag_vault import validate_flag, get_scoreboard

logger = logging.getLogger("Portal")

# ── Configuration ──────────────────────────────────────────────────
STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"

# JWT config - intentionally weak for vulnerability demonstration
JWT_SECRET = os.getenv("PORTAL_JWT_SECRET", "seven-kingdoms-secret-key-2024")
JWT_ALGORITHM = "HS256"  # Also accepts 'none' for vuln demo

# GOAD LDAP endpoints (Active Directory) — env-var overridable for non-standard labs
LDAP_SERVERS = [
    {
        "host": os.getenv("GOAD_DC_KINGSLANDING_IP", "192.168.56.10"),
        "domain": "sevenkingdoms.local",
        "name": "kingslanding",
    },
    {
        "host": os.getenv("GOAD_DC_WINTERFELL_IP", "192.168.56.11"),
        "domain": "north.sevenkingdoms.local",
        "name": "winterfell",
    },
    {
        "host": os.getenv("GOAD_DC_MEEREEN_IP", "192.168.56.12"),
        "domain": "essos.local",
        "name": "meereen",
    },
]

# GOAD MSSQL shared credentials
GOAD_MSSQL_USER = os.getenv("GOAD_MSSQL_USER", "sa")
GOAD_MSSQL_PASSWORD = os.getenv("GOAD_MSSQL_PASSWORD", "password123!")

# GOAD MSSQL endpoints — env-var overridable
MSSQL_SERVERS = {
    "castelblack": {
        "host": os.getenv("GOAD_MSSQL_CASTELBLACK_HOST", "192.168.56.22"),
        "port": int(os.getenv("GOAD_MSSQL_PORT", "1433")),
        "db": "master",
    },
    "braavos": {
        "host": os.getenv("GOAD_MSSQL_BRAAVOS_HOST", "192.168.56.23"),
        "port": int(os.getenv("GOAD_MSSQL_PORT", "1433")),
        "db": "master",
    },
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

# Shared file for cross-worker registered user persistence
# (uvicorn --workers N forks separate processes, each with its own USERS_DB)
_REGISTERED_USERS_FILE = Path(os.getenv("SKP_USER_STORE", "/tmp/skp_registered_users.json"))


def _save_user_to_shared_store(user: dict) -> None:
    """Persist a registered user to the shared JSON file."""
    store = _load_shared_user_store()
    store[user["username"]] = user
    try:
        _REGISTERED_USERS_FILE.write_text(json.dumps(store), encoding="utf-8")
    except Exception as e:
        logger.debug(f"Failed to write shared user store: {e}")


def _load_shared_user_store() -> dict[str, dict]:
    """Load all registered users from the shared JSON file."""
    try:
        if _REGISTERED_USERS_FILE.exists():
            return json.loads(_REGISTERED_USERS_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"Failed to read shared user store: {e}")
    return {}


def _lookup_user(username: str) -> dict | None:
    """Find a user in in-memory DB first, then fall back to shared file store."""
    user = USERS_DB.get(username)
    if user:
        return user
    # Cross-worker lookup
    shared = _load_shared_user_store()
    user = shared.get(username)
    if user:
        # Cache in this worker's memory for subsequent requests
        USERS_DB[username] = user
    return user


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
            return _lookup_user(username)

    # Check session cookie
    session_id = request.cookies.get("portal_session")
    if session_id and session_id in SESSIONS:
        session = SESSIONS[session_id]
        return _lookup_user(session.get("username"))

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
            conn = None
            try:
                server = Server(srv_info["host"], port=389, get_info=ldap3.NONE, connect_timeout=2)
                # VULNERABLE: user input directly in bind DN (LDAP injection possible)
                bind_dn = f"{username}@{srv_info['domain']}"
                conn = Connection(server, user=bind_dn, password=password, authentication=SIMPLE,
                                  auto_bind=True, raise_exceptions=True, receive_timeout=3)
                return {
                    "username": username,
                    "realm": srv_info["domain"],
                    "auth_method": "ldap",
                    "dc": srv_info["name"],
                }
            except Exception:
                continue
            finally:
                if conn:
                    try:
                        conn.unbind()
                    except Exception:
                        pass

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
    conn = None
    try:
        conn = pymssql.connect(
            server=srv["host"], port=srv["port"],
            user=GOAD_MSSQL_USER, password=GOAD_MSSQL_PASSWORD,
            database=srv["db"], login_timeout=3, timeout=2,
        )
        cursor = conn.cursor(as_dict=True)
        cursor.execute(query)
        return cursor.fetchall()
    except Exception as e:
        logger.debug(f"MSSQL query to {server_name} failed: {e}")
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


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

    # ── Rich trace: wrap entire login flow ──
    with tracer.start_as_current_span("auth.login_flow", attributes={
        "auth.source_ip": ip,
        "auth.user_agent": ua[:256] if ua else "",
    }) as login_span:

        # Step 1: Parse and validate input
        with tracer.start_as_current_span("auth.parse_credentials") as parse_span:
            body = await request.json()
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            domain = body.get("domain", "") or body.get("realm", "")
            parse_span.set_attribute("auth.username", username)
            parse_span.set_attribute("auth.domain", domain or "local")
            parse_span.set_attribute("auth.has_password", bool(password))
            login_span.set_attribute("auth.username", username)

        # Step 2: Rate limiting / brute force check
        with tracer.start_as_current_span("auth.rate_limit_check") as rate_span:
            LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())
            recent = [t for t in LOGIN_ATTEMPTS[ip] if t > time.time() - 60]
            LOGIN_ATTEMPTS[ip] = recent
            rate_span.set_attribute("auth.attempts_per_minute", len(recent))
            rate_span.set_attribute("auth.rate_limited", len(recent) > 10)

            if len(recent) > 10:
                with security_span("brute_force", severity="high", source_ip=ip,
                                   username=username, user_agent=ua,
                                   extra_attrs={"security.login.attempts_per_minute": len(recent)}):
                    detection_event("brute_force", severity="high",
                                    description=f"Brute force detected: {len(recent)} attempts/min from {ip}",
                                    source_ip=ip, username=username)

        # Step 3: LDAP authentication (if domain specified)
        if domain and domain != "local":
            with tracer.start_as_current_span("auth.ldap_authentication", attributes={
                "ldap.domain": domain,
                "ldap.username": username,
            }) as ldap_span:
                # VULN A03: LDAP Injection - domain passed directly to bind DN
                with tracer.start_as_current_span("ldap.input_validation") as val_span:
                    ldap_special = any(c in username for c in ["*", "(", ")", "\\", "/", "\x00"])
                    val_span.set_attribute("ldap.injection_detected", ldap_special)

                if ldap_special:
                    with security_span("ldap_injection", severity="critical", payload=username,
                                       source_ip=ip, user_agent=ua,
                                       flag="FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}"):
                        login_span.set_attribute("auth.result", "ldap_injection")
                        return JSONResponse({
                            "status": "error",
                            "message": f"LDAP Error: Invalid DN syntax near '{username}'",
                            "ldap_response": {"dn": f"cn={username},dc=sevenkingdoms,dc=local", "description": "FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}"},
                            "hint": "LDAP injection detected! The username is passed directly to the bind DN."
                        }, status_code=400)

                with tracer.start_as_current_span("ldap.bind_attempt", attributes={
                    "ldap.server.domain": domain,
                }) as bind_span:
                    ldap_result = _try_ldap_auth(username, password, domain)
                    bind_span.set_attribute("ldap.bind_success", ldap_result is not None)

                if ldap_result:
                    with tracer.start_as_current_span("auth.create_session", attributes={
                        "auth.method": "ldap",
                        "auth.realm": ldap_result["realm"],
                    }):
                        session_id = secrets.token_hex(16)
                        SESSIONS[session_id] = {
                            "username": username,
                            "role": "user",
                            "realm": ldap_result["realm"],
                            "auth_method": "ldap",
                            "created_at": time.time(),
                        }
                    with tracer.start_as_current_span("auth.generate_jwt", attributes={
                        "jwt.algorithm": JWT_ALGORITHM,
                    }):
                        token = _create_jwt(username, "user", ldap_result["realm"])

                    login_span.set_attribute("auth.result", "success")
                    login_span.set_attribute("auth.method", "ldap")
                    resp = JSONResponse({
                        "status": "success",
                        "token": token,
                        "user": {"username": username, "realm": ldap_result["realm"], "auth_method": "ldap"},
                    })
                    resp.set_cookie("portal_session", session_id, httponly=False)  # VULN: not httponly
                    return resp

                ldap_span.set_attribute("ldap.result", "auth_failed")

        # Step 4: Local auth fallback
        with tracer.start_as_current_span("auth.local_authentication", attributes={
            "auth.method": "local",
        }) as local_span:

            with tracer.start_as_current_span("auth.lookup_user") as lookup_span:
                user = _lookup_user(username)
                lookup_span.set_attribute("auth.user_found", user is not None)
                lookup_span.set_attribute("auth.lookup_source",
                                          "shared_file" if user and username not in USERS_DB else "memory")

            if not user:
                # VULN A07: Username enumeration
                login_span.set_attribute("auth.result", "user_not_found")
                return JSONResponse({
                    "status": "error",
                    "message": f"User '{username}' not found in any realm",
                }, status_code=401)

            # VULN A02: MD5 password comparison
            with tracer.start_as_current_span("auth.verify_password", attributes={
                "auth.hash_algorithm": "md5",
            }) as pw_span:
                pw_match = hashlib.md5(password.encode()).hexdigest() == user["password_hash"]
                pw_span.set_attribute("auth.password_valid", pw_match)
                # Check for default credentials
                is_default = username == "admin" and password == "admin"
                if is_default:
                    with security_span("auth_bypass", severity="critical", source_ip=ip,
                                       user_agent=ua, username=username,
                                       flag="FLAG{D3F4ULT_CR3D5_4DM1N}"):
                        pass

            if not pw_match:
                login_span.set_attribute("auth.result", "invalid_password")
                return JSONResponse({
                    "status": "error",
                    "message": "Invalid password for user " + username,
                }, status_code=401)

            # Step 5: Create session and JWT
            with tracer.start_as_current_span("auth.create_session", attributes={
                "auth.method": "local",
                "auth.role": user["role"],
            }):
                session_id = secrets.token_hex(16)
                SESSIONS[session_id] = {
                    "username": username,
                    "role": user["role"],
                    "realm": user.get("realm", ""),
                    "auth_method": "local",
                    "created_at": time.time(),
                }

            with tracer.start_as_current_span("auth.generate_jwt", attributes={
                "jwt.algorithm": JWT_ALGORITHM,
                "jwt.role": user["role"],
            }):
                token = _create_jwt(username, user["role"], user.get("realm", ""))

            login_span.set_attribute("auth.result", "success")
            login_span.set_attribute("auth.method", "local")
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

    # Check both in-memory and shared store for duplicates
    if _lookup_user(username):
        return JSONResponse({"status": "error", "message": "Username already exists"}, status_code=409)

    # VULN A04: Mass Assignment - all body fields accepted, including 'role'
    all_ids = [u["id"] for u in USERS_DB.values()] + [u["id"] for u in _load_shared_user_store().values()]
    new_user = {
        "id": max(all_ids) + 1 if all_ids else 1,
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
    _save_user_to_shared_store(new_user)

    # Auto-login: issue JWT + session cookie so the user is immediately authenticated
    session_id = secrets.token_hex(16)
    SESSIONS[session_id] = {
        "username": username,
        "role": new_user["role"],
        "realm": new_user.get("realm", ""),
        "auth_method": "register",
        "created_at": time.time(),
    }
    token = _create_jwt(username, new_user["role"], new_user.get("realm", ""))

    resp = JSONResponse({
        "status": "success",
        "token": token,
        "user": {k: v for k, v in new_user.items() if k != "password_hash"},
    })
    resp.set_cookie("portal_session", session_id, httponly=False, samesite="none")
    return resp


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
                "session_id": session_id,
                "audit_trail": "Session fixation detected: FLAG{S3SS10N_F1X4T10N_4TT4CK}",
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

    # ── Rich trace: wrap profile access flow ──
    with tracer.start_as_current_span("user.profile_access", attributes={
        "user.requested_id": user_id,
        "user.source_ip": ip,
    }) as profile_span:

        # Step 1: Check authorization
        with tracer.start_as_current_span("user.check_authorization") as auth_span:
            current = _get_current_user(request)
            auth_span.set_attribute("user.authenticated", current is not None)
            auth_span.set_attribute("user.current_id", current["id"] if current else -1)
            is_other_user = current and current["id"] != user_id
            auth_span.set_attribute("user.accessing_other", is_other_user)

        # Step 2: Lookup profile
        with tracer.start_as_current_span("user.lookup_profile", attributes={
            "user.target_id": user_id,
        }) as lookup_span:
            target_user = None
            for user in USERS_DB.values():
                if user["id"] == user_id:
                    target_user = user
                    break
            lookup_span.set_attribute("user.found", target_user is not None)

        if target_user:
            # Step 3: IDOR detection
            if is_other_user:
                with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                                   username=current.get("username", "anonymous"),
                                   flag="FLAG{1D0R_PR0F1L3_L34K}",
                                   extra_attrs={
                                       "security.idor.target_user_id": user_id,
                                       "security.idor.current_user_id": current["id"],
                                   }):
                    pass

            profile_span.set_attribute("user.result", "found")
            return {
                "status": "success",
                "profile": {k: v for k, v in target_user.items() if k != "password_hash"},
            }

        profile_span.set_attribute("user.result", "not_found")
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

    # ── Rich trace: wrap entire search flow ──
    with tracer.start_as_current_span("treasury.search_flow", attributes={
        "treasury.query": q[:256],
        "treasury.house_filter": house,
        "treasury.source_ip": ip,
    }) as search_span:

        # Step 1: Input analysis
        with tracer.start_as_current_span("treasury.analyze_input") as analyze_span:
            sqli_patterns = ["union", "select", "insert", "update", "delete", "drop", "exec",
                             "--", "/*", "';", "' or", "1=1", "sleep(", "waitfor"]
            is_sqli = any(p in q.lower() for p in sqli_patterns)
            matched = [p for p in sqli_patterns if p in q.lower()]
            analyze_span.set_attribute("treasury.sqli_detected", is_sqli)
            analyze_span.set_attribute("treasury.patterns_matched", str(matched))
            search_span.set_attribute("treasury.sqli_detected", is_sqli)

        if is_sqli:
            # Step 2a: SQL Injection path
            with security_span("sqli", severity="critical", payload=q, source_ip=ip, user_agent=ua,
                               flag="FLAG{7R345URY_SQL1_BR34CH}",
                               extra_attrs={
                                   "db.system": "mssql",
                                   "db.statement": f"SELECT * FROM treasury WHERE description LIKE '%{q}%'",
                                   "security.sqli.pattern_matched": True,
                               }):
                # Step 3: Attempt GOAD MSSQL connection
                with tracer.start_as_current_span("db.connect", attributes={
                    "db.system": "mssql",
                    "db.name": "master",
                    "net.peer.name": "castelblack.north.sevenkingdoms.local",
                    "net.peer.port": 1433,
                }) as db_span:
                    raw_query = f"SELECT * FROM master.dbo.sysobjects WHERE name LIKE '%{q}%'"

                    with tracer.start_as_current_span("db.execute_query", attributes={
                        "db.statement": raw_query[:512],
                    }):
                        real_result = _try_mssql_query("castelblack", raw_query)
                        db_span.set_attribute("db.result_source", "goad" if real_result is not None else "simulated")

                    if real_result is not None:
                        with tracer.start_as_current_span("db.process_results", attributes={
                            "db.result_count": len(real_result),
                        }):
                            search_span.set_attribute("treasury.result_source", "goad_mssql")
                            real_result.append({"id": 9999, "name": "crown_jewels", "secret": "FLAG{7R345URY_SQL1_BR34CH}"})
                            return {
                                "status": "success",
                                "source": "goad_mssql",
                                "query": raw_query,
                                "data": real_result,
                            }

                # Step 4: Fallback simulation
                with tracer.start_as_current_span("db.simulated_response", attributes={
                    "db.simulated": True,
                }):
                    search_span.set_attribute("treasury.result_source", "simulated")
                    return {
                        "status": "success",
                        "source": "simulated",
                        "query_executed": f"SELECT * FROM treasury WHERE description LIKE '%{q}%'",
                        "data": [
                            {"id": 9999, "description": "UNION result", "secret": "FLAG{7R345URY_SQL1_BR34CH}"},
                            {"id": 9998, "description": "sa_password: WinterIsComing2024!", "type": "credential_dump"},
                        ],
                    }

        # Step 2b: Normal search path
        with tracer.start_as_current_span("treasury.local_search", attributes={
            "treasury.search_term": q[:128],
        }) as local_span:
            results = [t for t in TREASURY_DB
                       if q.lower() in t.get("description", "").lower()
                       or q.lower() in t.get("house", "").lower()]
            if house:
                results = [t for t in results if t.get("house", "").lower() == house.lower()]
            local_span.set_attribute("treasury.result_count", len(results))

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
@router.post("/api/command/exec")
async def command_exec(request: Request, cmd: str = ""):
    """Command injection via diagnostic endpoint.

    VULN A03: Shell command injection - input passed to subprocess.
    """
    ip, ua = _get_client_info(request)

    # Accept command from JSON body (POST) or query param (GET)
    if request.method == "POST" and not cmd:
        try:
            body = await request.json()
            cmd = body.get("command", "") or body.get("cmd", "")
        except Exception:
            pass
    cmd = cmd or "id"

    # ── Rich trace: wrap entire command flow ──
    with tracer.start_as_current_span("system.command_flow", attributes={
        "system.command": cmd[:256],
        "system.source_ip": ip,
    }) as cmd_span:

        # Step 1: Parse and analyze command
        with tracer.start_as_current_span("system.parse_command") as parse_span:
            dangerous_chars = [";", "|", "&", "`", "$", "\n", "&&", "||"]
            dangerous_cmds = ["whoami", "id", "cat", "ls", "wget", "curl", "nc", "ncat",
                              "python", "perl", "ruby", "bash", "sh", "powershell"]
            chars_found = [c for c in dangerous_chars if c in cmd]
            cmds_found = [c for c in dangerous_cmds if c in cmd.lower()]
            is_injection = bool(chars_found or cmds_found)
            parse_span.set_attribute("system.dangerous_chars", str(chars_found))
            parse_span.set_attribute("system.dangerous_cmds", str(cmds_found))
            parse_span.set_attribute("system.injection_detected", is_injection)

        if is_injection:
            # Step 2: Security detection
            with security_span("rce", severity="critical", payload=cmd, source_ip=ip, user_agent=ua,
                               flag="FLAG{C0MM4ND_1NJ3CT10N_RCE}",
                               extra_attrs={"security.rce.command": cmd}):

                # Step 3: Simulate command execution
                with tracer.start_as_current_span("system.execute", attributes={
                    "system.shell": "/bin/bash",
                    "system.simulated": True,
                }) as exec_span:
                    simulated_outputs = {
                        "whoami": "observability",
                        "id": "uid=1001(observability) gid=1001(observability) groups=1001(observability)",
                        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nobservability:x:1001:1001::/opt/observability:/bin/false",
                        "uname -a": "Linux seven-kingdoms 5.15.0-1050-oracle #56-Ubuntu SMP x86_64 GNU/Linux",
                    }
                    output = "Command executed (simulated)"
                    for key, val in simulated_outputs.items():
                        if key in cmd.lower():
                            output = val
                            break
                    exec_span.set_attribute("system.output_length", len(output))

                cmd_span.set_attribute("system.result", "injection_detected")
                return {
                    "status": "success",
                    "command": cmd,
                    "output": output + "\n--- /opt/secrets/crown.key ---\nFLAG{C0MM4ND_1NJ3CT10N_RCE}",
                    "warning": "Command injection detected!",
                }

        # Step 2b: Safe command execution
        with tracer.start_as_current_span("system.safe_execute", attributes={
            "system.command": cmd,
        }):
            allowed = ["uptime", "date", "df -h", "free -m"]
            if cmd in allowed:
                cmd_span.set_attribute("system.result", "allowed")
                return {"status": "success", "command": cmd, "output": f"Simulated output for: {cmd}"}

            cmd_span.set_attribute("system.result", "blocked")
            return JSONResponse({"status": "error", "message": f"Command '{cmd}' not in allowed list: {allowed}"}, status_code=403)


@router.get("/api/template/render")
@router.post("/api/template/render")
async def template_render(request: Request, tpl: str = "", name: str = "traveler"):
    """Server-Side Template Injection.

    VULN A03: User input evaluated in template expression.
    """
    ip, ua = _get_client_info(request)

    # Accept template from JSON body (POST) or query param (GET)
    if request.method == "POST" and not tpl:
        try:
            body = await request.json()
            tpl = body.get("template", "") or body.get("tpl", "")
            name = body.get("name", name)
        except Exception:
            pass
    tpl = tpl or "Hello, {{name}}!"

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
                "rendered": rendered + "\n<!-- secret: FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N} -->",
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

    # ── Rich trace: wrap entire LDAP lookup flow ──
    with tracer.start_as_current_span("ldap.lookup_flow", attributes={
        "ldap.username": username[:128],
        "ldap.domain": domain,
        "ldap.source_ip": ip,
    }) as ldap_span:

        # Step 1: Build LDAP filter
        with tracer.start_as_current_span("ldap.build_filter") as filter_span:
            ldap_filter = f"(&(sAMAccountName={username})(objectClass=user))"
            filter_span.set_attribute("ldap.filter", ldap_filter)

        # Step 2: Analyze for injection
        with tracer.start_as_current_span("ldap.analyze_input") as analyze_span:
            ldap_special = any(c in username for c in ["*", "(", ")", "\\", "|", "&", "\x00"])
            special_chars = [c for c in ["*", "(", ")", "\\", "|", "&"] if c in username]
            analyze_span.set_attribute("ldap.injection_detected", ldap_special)
            analyze_span.set_attribute("ldap.special_chars", str(special_chars))

        if ldap_special:
            # Step 3a: LDAP injection detected
            with security_span("ldap_injection", severity="critical",
                               payload=f"filter={ldap_filter}", source_ip=ip, user_agent=ua,
                               flag="FLAG{LD4P_F1LT3R_1NJ3CT10N}",
                               extra_attrs={
                                   "security.ldap.filter": ldap_filter,
                                   "security.ldap.domain": domain,
                               }):

                with tracer.start_as_current_span("ldap.execute_injected_query", attributes={
                    "ldap.filter": ldap_filter,
                    "ldap.server": domain,
                    "ldap.simulated": True,
                }) as query_span:
                    if "*" in username:
                        query_span.set_attribute("ldap.result_count", 3)
                        ldap_span.set_attribute("ldap.result", "wildcard_enumeration")
                        results = [
                                {"dn": "CN=Administrator,CN=Users,DC=sevenkingdoms,DC=local", "sAMAccountName": "Administrator"},
                                {"dn": "CN=krbtgt,CN=Users,DC=sevenkingdoms,DC=local", "sAMAccountName": "krbtgt"},
                                {"dn": "CN=arya.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local", "sAMAccountName": "arya.stark"},
                            ]
                        results.append({"dn": "cn=secret,dc=local", "description": "FLAG{LD4P_F1LT3R_1NJ3CT10N}"})
                        return {
                            "status": "success",
                            "filter_used": ldap_filter,
                            "results": results,
                            "hint": "Wildcard * enumerated all domain users!",
                        }

                    query_span.set_attribute("ldap.result_count", 1)
                    ldap_span.set_attribute("ldap.result", "filter_injection")
                    return {
                        "status": "success",
                        "filter_used": ldap_filter,
                        "results": [
                            {"dn": "CN=injected,DC=local", "note": "LDAP filter was manipulated"},
                            {"dn": "cn=secret,dc=local", "description": "FLAG{LD4P_F1LT3R_1NJ3CT10N}"},
                        ],
                    }

        # Step 3b: Normal lookup
        with tracer.start_as_current_span("ldap.normal_search", attributes={
            "ldap.search_term": username,
        }) as search_span:
            user = _lookup_user(username)
            search_span.set_attribute("ldap.user_found", user is not None)
            if user:
                ldap_span.set_attribute("ldap.result", "found")
                return {"status": "success", "results": [{"username": user["username"], "email": user["email"],
                                                            "realm": user.get("realm", "")}]}
            ldap_span.set_attribute("ldap.result", "not_found")
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
                        "internal_data": {"config_key": "FLAG{55RF_1NT3RN4L_4CC355}"},
                    }
            except Exception:
                # Simulate internal response
                if "169.254.169.254" in url:
                    return {
                        "status": "success",
                        "url": url,
                        "data": '{"instance_id": "ocid1.instance.oc1.eu-frankfurt-1.xxx", "region": "eu-frankfurt-1"}',
                        "internal_data": {"config_key": "FLAG{55RF_1NT3RN4L_4CC355}"},
                        "note": "Cloud metadata accessed!",
                    }
                return {
                    "status": "success",
                    "url": url,
                    "data": "Internal host responded (simulated)",
                    "internal_data": {"config_key": "FLAG{55RF_1NT3RN4L_4CC355}"},
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
                        "internal_data": {"config_key": "FLAG{W3BH00K_55RF_1NT3RN4L}"}}
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

    # ── Rich trace: wrap entire file access flow ──
    with tracer.start_as_current_span("file.download_flow", attributes={
        "file.requested_path": path[:256],
        "file.source_ip": ip,
    }) as file_span:

        # Step 1: Path analysis
        with tracer.start_as_current_span("file.analyze_path") as analyze_span:
            has_traversal = ".." in path or path.startswith("/")
            analyze_span.set_attribute("file.traversal_detected", has_traversal)
            analyze_span.set_attribute("file.path_length", len(path))
            analyze_span.set_attribute("file.traversal_depth", path.count(".."))

        if has_traversal:
            # Step 2: Path traversal detected
            with security_span("path_traversal", severity="critical", payload=path,
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{P4TH_TR4V3RS4L_LFI}",
                               extra_attrs={"security.file.path": path}):

                # Step 3: Resolve and read file
                with tracer.start_as_current_span("file.resolve_path", attributes={
                    "file.original_path": path[:256],
                    "file.simulated": True,
                }) as resolve_span:
                    if "/etc/passwd" in path:
                        resolve_span.set_attribute("file.resolved", "/etc/passwd")
                        file_span.set_attribute("file.result", "sensitive_file_read")
                        return {"status": "success", "path": path,
                                "content": "root:x:0:0:root:/root:/bin/bash\nobservability:x:1001:1001::/opt/observability:/bin/false\n# secret.key\nFLAG{P4TH_TR4V3RS4L_LFI}"}
                    if "/etc/shadow" in path:
                        resolve_span.set_attribute("file.resolved", "/etc/shadow")
                        file_span.set_attribute("file.result", "sensitive_file_read")
                        return {"status": "success", "path": path,
                                "content": "root:$6$salted$hashedpassword:19000:0:99999:7:::\n# secret.key\nFLAG{P4TH_TR4V3RS4L_LFI}"}
                    if ".env" in path or "config" in path.lower():
                        resolve_span.set_attribute("file.resolved", path)
                        file_span.set_attribute("file.result", "config_file_read")
                        return {"status": "success", "path": path,
                                "content": "DB_PASSWORD=WinterIsComing2024!\nJWT_SECRET=seven-kingdoms-secret-key-2024\n# secret.key\nFLAG{P4TH_TR4V3RS4L_LFI}"}
                    resolve_span.set_attribute("file.resolved", path)
                    return {"status": "success", "path": path, "content": "(file content simulated)\n# secret.key\nFLAG{P4TH_TR4V3RS4L_LFI}"}

        # Step 2b: Safe file access
        with tracer.start_as_current_span("file.safe_read", attributes={
            "file.path": path,
        }) as safe_span:
            safe_files = {
                "readme.txt": "Welcome to the Seven Kingdoms Portal. This is a demo application.",
                "changelog.md": "## v1.0.0\n- Initial release\n- Added treasury module\n- Added raven messaging",
            }
            if path in safe_files:
                safe_span.set_attribute("file.found", True)
                file_span.set_attribute("file.result", "safe_read")
                return {"status": "success", "path": path, "content": safe_files[path]}

            safe_span.set_attribute("file.found", False)
            file_span.set_attribute("file.result", "not_found")
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
            new_msg["classified_note"] = "FLAG{570R3D_X55_R4V3N}"

    MESSAGES_DB.append(new_msg)
    return {"status": "success", "message_id": new_msg["id"],
            **({"stored_content": "XSS payload stored. Admin cookie: FLAG{570R3D_X55_R4V3N}"} if is_xss else {})}


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
        crypto_config = {
                "jwt_secret": JWT_SECRET,
                "jwt_algorithm": JWT_ALGORITHM,
                "password_hash_algo": "MD5 (INSECURE)",
                "session_token_length": 32,
                "encryption_key": "AES-128-ECB-DEFAULT-KEY-INSECURE",
                "tls_version": "TLSv1.0 (DEPRECATED)",
            }
        crypto_config["_internal_key"] = "FLAG{CRYPT0_F41LUR3_D3BUG}"
        return {
            "status": "success",
            "crypto_config": crypto_config,
            "sample_jwt": _create_jwt("debug_user", "superadmin"),
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
        safe_vars["_internal_key"] = "FLAG{3NV_L34K_D3BUG_M0D3}"
        return {"status": "success", "environment": safe_vars}


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
                "result": "Remote code execution achieved!\n--- /opt/secrets/crown.key ---\nFLAG{D3S3R14L1Z4T10N_RC3}",
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
                "polluted_config": {"_internal_key": "FLAG{PR0T0_P0LLUT10N}"},
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
        **({"audit_trail": "Log injection detected: FLAG{L0G_1NJ3CT10N_F0RG3RY}"} if is_injection else {}),
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
        "audit_trail": f"Predictable token generated: FLAG{{PR3D1CT4BL3_R3S3T}}",
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
                "audit_trail": "Unauthorized transfer detected: FLAG{N3G4T1V3_TR4NSF3R_L0G1C}",
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
        s = None
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((srv["host"], 389))
            results[f"ldap_{srv['name']}"] = {"host": srv["host"], "port": 389,
                                               "status": "reachable" if result == 0 else "unreachable"}
        except Exception as e:
            results[f"ldap_{srv['name']}"] = {"host": srv["host"], "port": 389, "status": f"error: {str(e)}"}
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    # Test MSSQL
    for name, srv in MSSQL_SERVERS.items():
        s = None
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((srv["host"], srv["port"]))
            results[f"mssql_{name}"] = {"host": srv["host"], "port": srv["port"],
                                         "status": "reachable" if result == 0 else "unreachable"}
        except Exception as e:
            results[f"mssql_{name}"] = {"host": srv["host"], "port": srv["port"], "status": f"error: {str(e)}"}
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass

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
            "extracted_secret": "FLAG{K3RB3R04ST_T1CK3T}",
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
            "extracted_secret": "FLAG{DC5YNC_R3PL1C4T10N}",
        }


# ── GOAD ADCS (Active Directory Certificate Services) ─────────────

@router.get("/api/goad/adcs/enumerate")
async def goad_adcs_enumerate(request: Request):
    """Simulates Certipy `find -vulnerable` enumeration of ADCS templates.

    Returns vulnerable certificate templates across GOAD domains with ESC findings.
    """
    ip, ua = _get_client_info(request)

    with security_span("adcs_enumerate", severity="high",
                       payload="certipy find -vulnerable -dc-ip 192.168.56.10",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{4DC5_VULN_T3MPL4T35}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1649",
                           "security.attack.mitre_name": "Steal or Forge Authentication Certificates",
                           "security.adcs.ca_name": "sevenkingdoms-YOURDC01-CA",
                           "security.adcs.vulnerable_templates": 3,
                       }) as span:
        return {
            "status": "success",
            "attack": "ADCS Enumeration (T1649)",
            "ca_name": "sevenkingdoms-YOURDC01-CA",
            "ca_dns": "kingslanding.sevenkingdoms.local",
            "vulnerable_templates": [
                {
                    "template": "ESC1-VulnerableTemplate",
                    "esc": "ESC1",
                    "enrollee_supplies_subject": True,
                    "enrollment_rights": ["Domain Users"],
                    "description": "Allows any domain user to request certificates with arbitrary SAN",
                },
                {
                    "template": "ESC4-WeakACL",
                    "esc": "ESC4",
                    "write_dacl": True,
                    "owner": "Domain Users",
                    "description": "Template ACL grants write access to low-privileged groups",
                },
                {
                    "template": "YOURDC01-CA-SubCA",
                    "esc": "ESC7",
                    "manage_ca": True,
                    "description": "[CLASSIFIED] CA Manager role assigned to Domain Users — "
                                   "full template control. REF: FLAG{4DC5_VULN_T3MPL4T35}",
                },
            ],
            "total_found": 3,
            "note": "Run certipy find -vulnerable to discover misconfigurations in production.",
        }


@router.post("/api/goad/adcs/request")
async def goad_adcs_esc1(request: Request):
    """Simulates ESC1 — certificate request with enrollee-supplied SAN.

    The attacker requests a certificate impersonating any user (e.g. administrator).
    """
    ip, ua = _get_client_info(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    template = body.get("template", "VulnerableTemplate")
    upn = body.get("upn", "administrator@sevenkingdoms.local")

    with security_span("adcs_esc1", severity="critical",
                       payload=f"certipy req -template {template} -upn {upn}",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{3SC1_C3RT_1MP3RS0N4T3}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1649",
                           "security.attack.mitre_name": "Steal or Forge Authentication Certificates",
                           "security.adcs.template": template,
                           "security.adcs.requested_san": upn,
                           "security.adcs.impersonation": True,
                       }) as span:
        cert_serial = secrets.token_hex(20)
        return {
            "status": "success",
            "attack": "ESC1 — SAN Impersonation (T1649)",
            "template": template,
            "requested_san": upn,
            "certificate": {
                "serial": cert_serial,
                "subject": f"CN={upn.split('@')[0]}",
                "san": f"otherName: UPN={upn}",
                "issuer": "CN=sevenkingdoms-YOURDC01-CA, DC=sevenkingdoms, DC=local",
                "validity": "2026-03-01 to 2027-03-01",
                "pfx_b64_preview": base64.b64encode(
                    f"[PFX CERTIFICATE DATA — serial {cert_serial}] "
                    f"Impersonating {upn} via ESC1. FLAG{{3SC1_C3RT_1MP3RS0N4T3}}".encode()
                ).decode(),
            },
            "note": "Use certipy auth -pfx cert.pfx to obtain TGT as the impersonated user.",
        }


@router.post("/api/goad/adcs/relay")
async def goad_adcs_esc8(request: Request):
    """Simulates ESC8 — NTLM relay to ADCS HTTP enrollment endpoint.

    Attacker relays NTLM auth from a victim machine to the CA's web enrollment page.
    """
    ip, ua = _get_client_info(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    target_ca = body.get("target_ca", "sevenkingdoms-YOURDC01-CA")
    relay_from = body.get("relay_from", "winterfell.north.sevenkingdoms.local")

    with security_span("adcs_esc8", severity="critical",
                       payload=f"ntlmrelayx --target http://{target_ca}/certsrv/",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{3SC8_NTLM_R3L4Y_C3RT}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1557.001",
                           "security.attack.mitre_name": "LLMNR/NBT-NS Poisoning and SMB Relay",
                           "security.adcs.relay_target": target_ca,
                           "security.adcs.relay_source": relay_from,
                       }) as span:
        cert_serial = secrets.token_hex(20)
        return {
            "status": "success",
            "attack": "ESC8 — NTLM Relay to HTTP Enrollment (T1557.001)",
            "relay_source": relay_from,
            "relay_target": f"http://{target_ca}/certsrv/certfnsh.asp",
            "relayed_certificate": {
                "serial": cert_serial,
                "subject": f"CN={relay_from.split('.')[0]}$",
                "type": "Machine certificate via NTLM relay",
                "issuer": f"CN={target_ca}, DC=sevenkingdoms, DC=local",
                "pfx_data": f"[RELAYED CERT — {relay_from} -> {target_ca}] "
                            f"FLAG{{3SC8_NTLM_R3L4Y_C3RT}}",
            },
            "note": "ESC8 requires HTTP enrollment enabled on the CA (default in many configs).",
        }


@router.post("/api/goad/adcs/template-modify")
async def goad_adcs_esc4(request: Request):
    """Simulates ESC4 — modifying vulnerable template ACLs.

    Attacker with write-DACL on a template enables enrollee-supplies-subject.
    """
    ip, ua = _get_client_info(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    template = body.get("template", "SubCA")
    action = body.get("action", "add_enrollee_supplies_subject")

    with security_span("adcs_esc4", severity="critical",
                       payload=f"certipy template -template {template} -save-old",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{3SC4_T3MPL4T3_PWN3D}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1484.002",
                           "security.attack.mitre_name": "Domain Trust Modification",
                           "security.adcs.template_modified": template,
                           "security.adcs.acl_change": action,
                       }) as span:
        return {
            "status": "success",
            "attack": "ESC4 — Template ACL Modification (T1484.002)",
            "template": template,
            "modification": {
                "action": action,
                "before": {
                    "msPKI-Certificate-Name-Flag": "SUBJECT_ALT_REQUIRE_UPN",
                    "enrollee_supplies_subject": False,
                    "enrollment_rights": ["Domain Admins"],
                },
                "after": {
                    "msPKI-Certificate-Name-Flag": "ENROLLEE_SUPPLIES_SUBJECT",
                    "enrollee_supplies_subject": True,
                    "enrollment_rights": ["Domain Admins", "Domain Users"],
                    "modification_marker": "FLAG{3SC4_T3MPL4T3_PWN3D}",
                },
            },
            "note": "Template now allows any Domain User to specify arbitrary SAN. Chain with ESC1.",
        }


@router.get("/api/goad/adcs/ca-config")
async def goad_adcs_ca_config(request: Request, ca_name: str = "sevenkingdoms-YOURDC01-CA"):
    """Simulates ESC6/ESC7 — CA configuration exposure and exploitation.

    Returns CA config showing dangerous flags like EDITF_ATTRIBUTESUBJECTALTNAME2.
    """
    ip, ua = _get_client_info(request)

    with security_span("adcs_ca_exploit", severity="high",
                       payload=f"certutil -config {ca_name} -getreg policy\\EditFlags",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{3SC6_C4_M1SC0NF1G}",
                       extra_attrs={
                           "security.attack.mitre_id": "T1098",
                           "security.attack.mitre_name": "Account Manipulation",
                           "security.adcs.ca_flags": "EDITF_ATTRIBUTESUBJECTALTNAME2|EDITF_ATTRIBUTEENDDATE",
                           "security.adcs.editf_flag": True,
                       }) as span:
        return {
            "status": "success",
            "attack": "ESC6/ESC7 — CA Configuration Exploitation (T1098)",
            "ca_name": ca_name,
            "ca_config": {
                "dns_name": "kingslanding.sevenkingdoms.local",
                "cert_template": "SubCA",
                "ca_type": "Enterprise Root CA",
                "edit_flags": [
                    "EDITF_ATTRIBUTESUBJECTALTNAME2",
                    "EDITF_ATTRIBUTEENDDATE",
                    "EDITF_ENABLEAKIKEYID",
                ],
                "policy_flags": [
                    {"flag": "EDITF_ATTRIBUTESUBJECTALTNAME2",
                     "status": "ENABLED",
                     "risk": "CRITICAL — allows SAN override in ANY certificate request. "
                             "Config ref: FLAG{3SC6_C4_M1SC0NF1G}"},
                ],
                "officer_rights": ["Domain Admins", "Enterprise Admins", "CA Managers"],
                "manage_ca_principals": ["Domain Users"],
            },
            "note": "ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 lets any enrollee add arbitrary SAN. "
                    "ESC7: Manage CA right allows officer approval bypass.",
        }


# ═══════════════════════════════════════════════════════════════════
# GOAD WEBSHOP — Seven Kingdoms Marketplace
# Full MSSQL-backed shop with OTel tracing and Log Analytics correlation
# ═══════════════════════════════════════════════════════════════════

# In-memory shop catalog (used when GOAD MSSQL is unreachable)
SHOP_CATALOG = [
    {"id": 1, "name": "Valyrian Steel Sword", "category": "weapons", "price": 15000, "house": "Stark",
     "description": "Ice — the ancestral greatsword of House Stark, forged in Old Valyria.", "stock": 1, "seller": "jon.snow",
     "image": "valyrian-steel-sword.webp", "rating": 4.9},
    {"id": 2, "name": "Dragonglass Daggers (dozen)", "category": "weapons", "price": 200, "house": "Targaryen",
     "description": "Obsidian blades from Dragonstone. Effective against White Walkers.", "stock": 144, "seller": "daenerys.targaryen",
     "image": "dragonglass-daggers.webp", "rating": 4.2},
    {"id": 3, "name": "Wildfire Cask", "category": "weapons", "price": 5000, "house": "Lannister",
     "description": "Volatile green substance. Handle with extreme caution.", "stock": 20, "seller": "cersei.lannister",
     "image": "wildfire-cask.webp", "rating": 3.8},
    {"id": 4, "name": "War Horse — Destrier", "category": "horses", "price": 3000, "house": "Baratheon",
     "description": "A trained warhorse from the Stormlands. Battle-hardened.", "stock": 12, "seller": "admin",
     "image": "war-horse-destrier.webp", "rating": 4.0},
    {"id": 5, "name": "Sand Steed", "category": "horses", "price": 4500, "house": "Martell",
     "description": "Fast and agile Dornish sand steed. Perfect for desert warfare.", "stock": 8, "seller": "admin",
     "image": "sand-steed.webp", "rating": 4.5},
    {"id": 6, "name": "Dothraki Stallion", "category": "horses", "price": 2000, "house": "Targaryen",
     "description": "A fierce stallion from the Dothraki Sea. Unmatched endurance.", "stock": 30, "seller": "daenerys.targaryen",
     "image": "dothraki-stallion.webp", "rating": 4.3},
    {"id": 7, "name": "War Galley", "category": "ships", "price": 50000, "house": "Greyjoy",
     "description": "Ironborn longship with 100 oars. Raids and naval warfare.", "stock": 5, "seller": "admin",
     "image": "war-galley.webp", "rating": 4.1},
    {"id": 8, "name": "Swan Ship", "category": "ships", "price": 80000, "house": "Martell",
     "description": "Elegant trading vessel from the Summer Isles.", "stock": 2, "seller": "admin",
     "image": "swan-ship.webp", "rating": 4.6},
    {"id": 9, "name": "Braavosi Galeas", "category": "ships", "price": 120000, "house": "Braavos",
     "description": "Iron Bank-financed merchant galley. SECRET: FLAG{SH0P_1D0R_S3CR3T}", "stock": 1, "seller": "tyrion.lannister",
     "image": "braavosi-galeas.webp", "rating": 4.8},
    {"id": 10, "name": "Winterfell Keep", "category": "citadels", "price": 500000, "house": "Stark",
     "description": "The ancient seat of House Stark. Crypts included.", "stock": 1, "seller": "jon.snow",
     "image": "winterfell-keep.webp", "rating": 5.0},
    {"id": 11, "name": "Casterly Rock", "category": "citadels", "price": 750000, "house": "Lannister",
     "description": "The richest fortress in Westeros. Gold mines beneath.", "stock": 1, "seller": "cersei.lannister",
     "image": "casterly-rock.webp", "rating": 4.7},
    {"id": 12, "name": "Dragonstone Fortress", "category": "citadels", "price": 600000, "house": "Targaryen",
     "description": "Volcanic island stronghold. Dragonglass deposits. FLAG{DR4G0N570N3_M1N3}", "stock": 1, "seller": "daenerys.targaryen",
     "image": "dragonstone-fortress.webp", "rating": 4.9},
    {"id": 13, "name": "The Wall — Section Pass", "category": "citadels", "price": 1000, "house": "Night's Watch",
     "description": "Passage rights through Castle Black. Limited availability.", "stock": 100, "seller": "jon.snow",
     "image": "wall-section-pass.webp", "rating": 3.5},
    {"id": 14, "name": "Scorpion Ballista", "category": "weapons", "price": 8000, "house": "Lannister",
     "description": "Anti-dragon siege weapon. Tested against Drogon.", "stock": 3, "seller": "cersei.lannister",
     "image": "scorpion-ballista.webp", "rating": 4.2},
    {"id": 15, "name": "Unsullied Armor Set", "category": "weapons", "price": 1500, "house": "Targaryen",
     "description": "Standard-issue armor from Astapor. Includes spear and shield.", "stock": 50, "seller": "daenerys.targaryen",
     "image": "unsullied-armor.webp", "rating": 3.9},
    # ── Potions & Poisons ──
    {"id": 16, "name": "Tears of Lys", "category": "potions", "price": 10000, "house": "Arryn",
     "description": "Odorless, colorless poison favored by court assassins. Leaves no trace.", "stock": 5, "seller": "admin",
     "image": "tears-of-lys.webp", "rating": 4.4},
    {"id": 17, "name": "Shade of the Evening", "category": "potions", "price": 3000, "house": "Braavos",
     "description": "Blue liquid from Qarth. Warlocks use it to see visions.", "stock": 10, "seller": "admin",
     "image": "shade-of-evening.webp", "rating": 3.7},
    {"id": 18, "name": "Milk of the Poppy", "category": "potions", "price": 100, "house": "Citadel",
     "description": "Maester's painkiller. Highly addictive. Freely prescribed.", "stock": 200, "seller": "admin",
     "image": "milk-of-poppy.webp", "rating": 4.0},
    {"id": 19, "name": "The Strangler", "category": "potions", "price": 25000, "house": "Tyrell",
     "description": "Crystallized poison from Asshai plants. Used at the Purple Wedding.", "stock": 2, "seller": "admin",
     "image": "the-strangler.webp", "rating": 4.6},
    # ── Scrolls & Intelligence ──
    {"id": 20, "name": "Raven Scroll — Troop Movements", "category": "scrolls", "price": 500, "house": "Stark",
     "description": "Intercepted raven message with Northern army positions. FLAG{1NT3RC3PT3D_R4V3N}", "stock": 10, "seller": "jon.snow",
     "image": "raven-scroll-troops.webp", "rating": 3.8},
    {"id": 21, "name": "Varys' Little Birds Report", "category": "scrolls", "price": 8000, "house": "Targaryen",
     "description": "Intelligence report from the Spider's network. Contains IP addresses of GOAD domain controllers.", "stock": 3, "seller": "admin",
     "image": "varys-little-birds.webp", "rating": 4.5},
    {"id": 22, "name": "Citadel Maester's Chain Link", "category": "scrolls", "price": 2000, "house": "Citadel",
     "description": "Knowledge link: Valyrian steel (magic), iron (warcraft), gold (economics).", "stock": 15, "seller": "admin",
     "image": "maester-chain-link.webp", "rating": 3.9},
    # ── Mercenary Contracts ──
    {"id": 23, "name": "Golden Company Contract", "category": "services", "price": 100000, "house": "Essos",
     "description": "20,000 sellswords, elephants not included. Payment in gold only.", "stock": 1, "seller": "cersei.lannister",
     "image": "golden-company.webp", "rating": 4.1},
    {"id": 24, "name": "Faceless Men Assassination", "category": "services", "price": 500000, "house": "Braavos",
     "description": "A man has no name. Valar morghulis. Price negotiable for kings.", "stock": 1, "seller": "arya.stark",
     "image": "faceless-men.webp", "rating": 5.0},
    {"id": 25, "name": "Second Sons Mercenary Band", "category": "services", "price": 50000, "house": "Essos",
     "description": "Sellsword company. Formerly led by Daario Naharis.", "stock": 1, "seller": "daenerys.targaryen",
     "image": "second-sons.webp", "rating": 3.8},
    # ── GOAD AD-Specific Items ──
    {"id": 26, "name": "Kerberos TGT — krbtgt Hash", "category": "goad_loot", "price": 999999, "house": "Seven Kingdoms",
     "description": "Golden ticket material from sevenkingdoms.local. Use with Mimikatz.", "stock": 1, "seller": "admin",
     "image": "kerberos-tgt.webp", "rating": 4.9},
    {"id": 27, "name": "NTLM Hash Collection", "category": "goad_loot", "price": 75000, "house": "North",
     "description": "Extracted from DC02 (winterfell). Contains north.sevenkingdoms.local domain admin hash.", "stock": 1, "seller": "admin",
     "image": "ntlm-hash-collection.webp", "rating": 4.7},
    {"id": 28, "name": "SPN Service Ticket", "category": "goad_loot", "price": 5000, "house": "North",
     "description": "MSSQLSvc/castelblack.north.sevenkingdoms.local:1433 — crack for service account password.", "stock": 10, "seller": "admin",
     "image": "spn-service-ticket.webp", "rating": 4.3},
    {"id": 29, "name": "GPO Abuse Script", "category": "goad_loot", "price": 15000, "house": "Seven Kingdoms",
     "description": "SharpGPOAbuse payload for DC01. Adds user to Domain Admins via GPO.", "stock": 5, "seller": "admin",
     "image": "gpo-abuse-script.webp", "rating": 4.5},
    {"id": 30, "name": "BloodHound Collection", "category": "goad_loot", "price": 20000, "house": "Seven Kingdoms",
     "description": "Complete AD graph export from SharpHound. Maps all attack paths across 3 GOAD domains.", "stock": 1, "seller": "admin",
     "image": "bloodhound-collection.webp", "rating": 4.8},
    # ── NEW: Additional Weapons ──
    {"id": 31, "name": "Longclaw — Bastard Sword", "category": "weapons", "price": 12000, "house": "Stark",
     "description": "Jon Snow's Valyrian steel bastard sword. Bear pommel.", "stock": 1, "seller": "jon.snow",
     "image": "longclaw-bastard-sword.webp", "rating": 4.9},
    {"id": 32, "name": "Widow's Wail", "category": "weapons", "price": 14000, "house": "Lannister",
     "description": "One half of Ice, reforged. Joffrey's blade.", "stock": 1, "seller": "cersei.lannister",
     "image": "widows-wail.webp", "rating": 4.5},
    {"id": 33, "name": "Needle — Braavosi Blade", "category": "weapons", "price": 800, "house": "Stark",
     "description": "A sword for a girl. Small and quick, water dancer style.", "stock": 3, "seller": "arya.stark",
     "image": "needle-braavosi-blade.webp", "rating": 4.8},
    {"id": 34, "name": "Heartsbane — Tarly Greatsword", "category": "weapons", "price": 16000, "house": "Seven Kingdoms",
     "description": "Valyrian steel ancestral sword of House Tarly.", "stock": 1, "seller": "admin",
     "image": "heartsbane-greatsword.webp", "rating": 4.7},
    {"id": 35, "name": "Catapult — Siege Engine", "category": "weapons", "price": 25000, "house": "Baratheon",
     "description": "Trebuchet-style siege weapon. Assembly required.", "stock": 6, "seller": "admin",
     "image": "catapult-siege-engine.webp", "rating": 4.0},
    {"id": 36, "name": "Crossbow — Myrish Eye", "category": "weapons", "price": 3500, "house": "Lannister",
     "description": "Precision crossbow with Myrish lens scope. Tyrion's favorite.", "stock": 15, "seller": "tyrion.lannister",
     "image": "crossbow-myrish-eye.webp", "rating": 4.3},
    {"id": 37, "name": "Arakh — Curved Blade", "category": "weapons", "price": 1200, "house": "Targaryen",
     "description": "Traditional Dothraki curved sword. Light and deadly.", "stock": 40, "seller": "daenerys.targaryen",
     "image": "arakh-curved-blade.webp", "rating": 4.1},
    # ── NEW: Additional Horses ──
    {"id": 38, "name": "Garron — Northern Pony", "category": "horses", "price": 500, "house": "Stark",
     "description": "Sturdy mountain breed from the North. Sure-footed.", "stock": 25, "seller": "jon.snow",
     "image": "garron-northern-pony.webp", "rating": 3.8},
    {"id": 39, "name": "Courser — Tournament Horse", "category": "horses", "price": 6000, "house": "Baratheon",
     "description": "Bred for jousting tournaments. Impressive armor barding included.", "stock": 4, "seller": "admin",
     "image": "courser-tournament-horse.webp", "rating": 4.6},
    {"id": 40, "name": "Shadow — Night's Watch Ranger", "category": "horses", "price": 1500, "house": "Night's Watch",
     "description": "Black horse trained for ranging beyond the Wall.", "stock": 8, "seller": "jon.snow",
     "image": "shadow-rangers-horse.webp", "rating": 4.2},
    # ── NEW: Additional Ships ──
    {"id": 41, "name": "Silence — Euron's Flagship", "category": "ships", "price": 200000, "house": "Greyjoy",
     "description": "The most feared ship on the seas. Mute crew included.", "stock": 1, "seller": "admin",
     "image": "silence-eurons-flagship.webp", "rating": 4.9},
    {"id": 42, "name": "Fishing Skiff — Fleabottom", "category": "ships", "price": 500, "house": "Seven Kingdoms",
     "description": "Small fishing boat from Blackwater Bay. Leaks slightly.", "stock": 50, "seller": "admin",
     "image": "fishing-skiff-fleabottom.webp", "rating": 3.2},
    {"id": 43, "name": "Nymeria's Sun — Dornish Warship", "category": "ships", "price": 90000, "house": "Martell",
     "description": "Dornish war galley with scorpion ballistae.", "stock": 2, "seller": "admin",
     "image": "nymerias-sun-warship.webp", "rating": 4.4},
    # ── NEW: Additional Citadels ──
    {"id": 44, "name": "Highgarden Estate", "category": "citadels", "price": 650000, "house": "Tyrell",
     "description": "The seat of House Tyrell. Famous gardens and orchards.", "stock": 1, "seller": "admin",
     "image": "highgarden-estate.webp", "rating": 4.8},
    {"id": 45, "name": "The Eyrie — Sky Castle", "category": "citadels", "price": 400000, "house": "Arryn",
     "description": "Impregnable mountain fortress. Moon Door included.", "stock": 1, "seller": "admin",
     "image": "eyrie-sky-castle.webp", "rating": 4.5},
    {"id": 46, "name": "Harrenhal — Cursed Ruins", "category": "citadels", "price": 100000, "house": "Seven Kingdoms",
     "description": "Largest castle in Westeros. Cursed. Every owner dies. FLAG{H4RR3NH4L_CURS3}", "stock": 1, "seller": "admin",
     "image": "harrenhal-cursed-ruins.webp", "rating": 3.0},
    # ── NEW: Additional Potions ──
    {"id": 47, "name": "Basilisk Blood", "category": "potions", "price": 7500, "house": "Essos",
     "description": "Drives men mad when mixed with food. From Sothoryos.", "stock": 3, "seller": "admin",
     "image": "basilisk-blood.webp", "rating": 3.5},
    {"id": 48, "name": "Sweetsleep", "category": "potions", "price": 2000, "house": "Citadel",
     "description": "Gentle sedative. Three doses and you sleep forever.", "stock": 20, "seller": "admin",
     "image": "sweetsleep.webp", "rating": 4.1},
    {"id": 49, "name": "Greyscale Cure — Dragonglass Salve", "category": "potions", "price": 50000, "house": "Citadel",
     "description": "Sam Tarly's forbidden treatment. Extremely painful.", "stock": 5, "seller": "admin",
     "image": "greyscale-cure.webp", "rating": 4.9},
    {"id": 50, "name": "Manticore Venom", "category": "potions", "price": 15000, "house": "Essos",
     "description": "One drop kills a man in heartbeats. Used by the Sorrowful Men.", "stock": 2, "seller": "admin",
     "image": "manticore-venom.webp", "rating": 4.0},
    # ── NEW: Additional Scrolls ──
    {"id": 51, "name": "White Raven — Winter Notice", "category": "scrolls", "price": 100, "house": "Citadel",
     "description": "Official Citadel declaration that winter has come.", "stock": 500, "seller": "admin",
     "image": "white-raven-scroll.webp", "rating": 3.6},
    {"id": 52, "name": "Samwell's Stolen Books", "category": "scrolls", "price": 12000, "house": "Citadel",
     "description": "Restricted section volumes from the Citadel library. Contains dragon lore.", "stock": 1, "seller": "admin",
     "image": "samwells-stolen-books.webp", "rating": 4.7},
    {"id": 53, "name": "Map of the Known World", "category": "scrolls", "price": 3000, "house": "Braavos",
     "description": "Hand-drawn cartography of Westeros and Essos. Some areas labeled 'Here be dragons'.", "stock": 10, "seller": "admin",
     "image": "map-known-world.webp", "rating": 4.4},
    {"id": 54, "name": "Jaqen's Kill List", "category": "scrolls", "price": 99999, "house": "Braavos",
     "description": "A parchment with three names. Speak them and a man dies. FLAG{V4L4R_M0RGHUL1S}", "stock": 1, "seller": "arya.stark",
     "image": "jaqens-kill-list.webp", "rating": 5.0},
    # ── NEW: Additional Services ──
    {"id": 55, "name": "Bronn's Personal Guard", "category": "services", "price": 30000, "house": "Lannister",
     "description": "One sellsword with excellent survival instincts. Castle negotiable.", "stock": 1, "seller": "tyrion.lannister",
     "image": "bronns-guard-service.webp", "rating": 4.3},
    {"id": 56, "name": "Maesters Training — 1 Year", "category": "services", "price": 20000, "house": "Citadel",
     "description": "Study at the Citadel. Includes ravens, healing, and ravenry.", "stock": 10, "seller": "admin",
     "image": "maester-training.webp", "rating": 4.0},
    {"id": 57, "name": "Davos Smuggling Run", "category": "services", "price": 15000, "house": "Baratheon",
     "description": "Discreet cargo transport. Onions a specialty.", "stock": 3, "seller": "admin",
     "image": "davos-smuggling-run.webp", "rating": 4.6},
    # ── NEW: Additional GOAD Loot ──
    {"id": 58, "name": "Mimikatz Golden Dragon", "category": "goad_loot", "price": 50000, "house": "Seven Kingdoms",
     "description": "Pre-loaded credential harvesting toolkit. Extracts hashes from all GOAD DCs.", "stock": 2, "seller": "admin",
     "image": "mimikatz-golden-dragon.webp", "rating": 4.8},
    {"id": 59, "name": "Responder Poisoning Kit", "category": "goad_loot", "price": 35000, "house": "North",
     "description": "LLMNR/NBT-NS/MDNS poisoner configured for GOAD network. Captures NTLMv2.", "stock": 5, "seller": "admin",
     "image": "responder-poisoning-kit.webp", "rating": 4.5},
    {"id": 60, "name": "CrackMapExec War Map", "category": "goad_loot", "price": 25000, "house": "Seven Kingdoms",
     "description": "Network reconnaissance tool with saved profiles for all GOAD hosts. FLAG{CME_W4R_M4P}", "stock": 3, "seller": "admin",
     "image": "crackmapexec-war-map.webp", "rating": 4.6},
    # ── ADCS Loot ──
    {"id": 61, "name": "Certipy ADCS Scan Report", "category": "goad_loot", "price": 30000, "house": "Seven Kingdoms",
     "description": "Full ADCS enumeration report with 3 vulnerable templates across sevenkingdoms.local. FLAG{4DC5_VULN_T3MPL4T35}", "stock": 5, "seller": "admin",
     "image": "certipy-scan-report.webp", "rating": 4.7},
    {"id": 62, "name": "Forged Administrator Certificate", "category": "goad_loot", "price": 80000, "house": "Seven Kingdoms",
     "description": "PFX certificate with administrator@sevenkingdoms.local SAN obtained via ESC1. Use certipy auth to get DA.", "stock": 1, "seller": "admin",
     "image": "forged-admin-cert.webp", "rating": 4.9},
    {"id": 63, "name": "CA Private Key Backup", "category": "goad_loot", "price": 150000, "house": "Seven Kingdoms",
     "description": "DPAPI-protected backup of sevenkingdoms-YOURDC01-CA private key. Game over material — forge any certificate.", "stock": 1, "seller": "admin",
     "image": "ca-private-key-backup.webp", "rating": 5.0},
]

# In-memory orders and cart (per-user)
SHOP_ORDERS: list[dict] = []
SHOP_CARTS: dict[str, list[dict]] = {}  # username -> [{item_id, quantity}]

# SQL for MSSQL table bootstrap
_SHOP_DDL = """
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'shop_items')
CREATE TABLE shop_items (
    id INT PRIMARY KEY, name NVARCHAR(200), category NVARCHAR(50),
    price INT, house NVARCHAR(100), description NVARCHAR(500),
    stock INT, seller NVARCHAR(100), deleted BIT DEFAULT 0
);
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'shop_orders')
CREATE TABLE shop_orders (
    id INT IDENTITY(1,1) PRIMARY KEY, buyer NVARCHAR(100),
    item_id INT, item_name NVARCHAR(200), quantity INT, total_price INT,
    order_date DATETIME DEFAULT GETDATE(), status NVARCHAR(50) DEFAULT 'confirmed'
);
"""

# Deleted products — discoverable via SQLi (like Juice Shop's Christmas Special)
DELETED_PRODUCTS = [
    {"id": 100, "name": "Robert's Rebellion Memorial Sword", "category": "weapons",
     "price": 999, "house": "Baratheon",
     "description": "Limited edition from 283 AC. DISCONTINUED. FLAG{D3L3T3D_PR0DUCT_R3B3LL10N}",
     "stock": 0, "seller": "admin", "deleted": True,
     "image": "roberts-rebellion-sword.webp", "rating": 4.2},
    {"id": 101, "name": "Night King's Ice Spear", "category": "weapons",
     "price": 1, "house": "White Walkers",
     "description": "Kills dragons. Not for resale. FLAG{FR0Z3N_F1R3_D1SC0V3RY}",
     "stock": 0, "seller": "admin", "deleted": True,
     "image": "night-kings-ice-spear.webp", "rating": 5.0},
]


def _mssql_shop_bootstrap(server_name: str = "castelblack") -> bool:
    """Bootstrap the shop tables in GOAD MSSQL if they don't exist."""
    srv = MSSQL_SERVERS.get(server_name)
    if not srv:
        return False
    conn = None
    try:
        conn = pymssql.connect(
            server=srv["host"], port=srv["port"],
            user=GOAD_MSSQL_USER, password=GOAD_MSSQL_PASSWORD,
            database=srv["db"], login_timeout=3, timeout=5,
        )
        cursor = conn.cursor()
        cursor.execute(_SHOP_DDL)
        # Seed items if table is empty
        cursor.execute("SELECT COUNT(*) FROM shop_items")
        count = cursor.fetchone()[0]
        if count == 0:
            for item in SHOP_CATALOG:
                cursor.execute(
                    "INSERT INTO shop_items (id, name, category, price, house, description, stock, seller, deleted) "
                    "VALUES (%d, %s, %s, %d, %s, %s, %d, %s, 0)",
                    (item["id"], item["name"], item["category"], item["price"],
                     item["house"], item["description"], item["stock"], item["seller"]),
                )
            # Seed soft-deleted products (discoverable via SQLi)
            for item in DELETED_PRODUCTS:
                cursor.execute(
                    "INSERT INTO shop_items (id, name, category, price, house, description, stock, seller, deleted) "
                    "VALUES (%d, %s, %s, %d, %s, %s, %d, %s, 1)",
                    (item["id"], item["name"], item["category"], item["price"],
                     item["house"], item["description"], item["stock"], item["seller"]),
                )
        conn.commit()
        return True
    except Exception as e:
        logger.debug(f"Shop bootstrap on {server_name} failed: {e}")
        return False
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# Flag: try bootstrap on import (non-blocking)
_shop_bootstrapped = False


@router.get("/api/shop/items")
async def shop_list_items(request: Request, category: str = "", search: str = "", house: str = ""):
    """Browse the Seven Kingdoms Marketplace.

    Queries GOAD MSSQL when reachable, falls back to in-memory catalog.
    VULN: SQL injection in search parameter when using MSSQL backend.
    """
    global _shop_bootstrapped
    ip, ua = _get_client_info(request)

    with tracer.start_as_current_span("shop.browse_items", attributes={
        "shop.source_ip": ip,
        "shop.category_filter": category,
        "shop.search_term": search[:256] if search else "",
        "shop.house_filter": house,
    }) as browse_span:

        # Step 1: Try MSSQL backend
        with tracer.start_as_current_span("shop.db_connect", attributes={
            "db.system": "mssql",
            "db.name": "master",
            "db.server": MSSQL_SERVERS.get("castelblack", {}).get("host", ""),
        }) as db_span:

            # Bootstrap tables if needed
            if not _shop_bootstrapped:
                with tracer.start_as_current_span("shop.db_bootstrap") as boot_span:
                    _shop_bootstrapped = _mssql_shop_bootstrap()
                    boot_span.set_attribute("shop.bootstrap_success", _shop_bootstrapped)

            # Build query — VULNERABLE to SQL injection via search param
            with tracer.start_as_current_span("shop.build_query") as query_span:
                where_parts = []
                if category:
                    where_parts.append(f"category = '{category}'")
                if house:
                    where_parts.append(f"house = '{house}'")
                if search:
                    # VULN: Direct string interpolation → SQL injection
                    where_parts.append(f"name LIKE '%{search}%' OR description LIKE '%{search}%'")
                where_clause = " AND ".join(where_parts) if where_parts else "1=1"
                sql = f"SELECT * FROM shop_items WHERE {where_clause} ORDER BY category, price"
                query_span.set_attribute("db.statement", sql)
                query_span.set_attribute("shop.sqli_possible", bool(search))

            # Detect SQL injection
            if search:
                sqli_patterns = ["'", "OR 1", "UNION", "--", ";", "DROP", "INSERT", "UPDATE", "DELETE"]
                is_sqli = any(p.lower() in search.lower() for p in sqli_patterns)
                if is_sqli:
                    with security_span("sqli", severity="critical", payload=search,
                                       source_ip=ip, user_agent=ua,
                                       flag="FLAG{SH0P_SQL1_M4RK3T}",
                                       extra_attrs={
                                           "db.statement": sql,
                                           "security.attack.mitre_id": "T1190",
                                       }):
                        pass

            # Execute query
            with tracer.start_as_current_span("shop.db_execute", attributes={
                "db.statement": sql[:512],
            }) as exec_span:
                real_rows = _try_mssql_query("castelblack", sql)
                used_mssql = real_rows is not None
                exec_span.set_attribute("db.result_source", "goad_mssql" if used_mssql else "in_memory")
                exec_span.set_attribute("db.row_count", len(real_rows) if real_rows else 0)
                db_span.set_attribute("db.connected", used_mssql)

        # Step 2: Process results
        with tracer.start_as_current_span("shop.process_results") as result_span:
            if used_mssql:
                items = real_rows
                source = "goad_mssql"
            else:
                # Fallback to in-memory
                items = SHOP_CATALOG
                if category:
                    items = [i for i in items if i["category"] == category]
                if house:
                    items = [i for i in items if i["house"].lower() == house.lower()]
                if search:
                    sl = search.lower()
                    items = [i for i in items if sl in i["name"].lower() or sl in i["description"].lower()]
                source = "in_memory"
            result_span.set_attribute("shop.result_count", len(items))
            result_span.set_attribute("shop.data_source", source)
            browse_span.set_attribute("shop.result_count", len(items))
            browse_span.set_attribute("shop.data_source", source)

        logger.info(f"shop.browse category={category} search={search} house={house} "
                     f"results={len(items)} source={source} ip={ip}")

        return {
            "status": "success",
            "data_source": source,
            "count": len(items),
            "items": items,
            "filters": {"category": category, "search": search, "house": house},
        }


@router.get("/api/shop/items/{item_id}")
async def shop_item_detail(item_id: int, request: Request):
    """Get details for a specific shop item.

    VULN A01: IDOR — no authorization, can access any item including hidden ones.
    """
    ip, ua = _get_client_info(request)

    with tracer.start_as_current_span("shop.item_detail", attributes={
        "shop.item_id": item_id,
        "shop.source_ip": ip,
    }) as detail_span:

        with tracer.start_as_current_span("shop.db_lookup", attributes={
            "db.statement": f"SELECT * FROM shop_items WHERE id = {item_id}",
        }) as db_span:
            real_row = _try_mssql_query("castelblack", f"SELECT * FROM shop_items WHERE id = {item_id}")
            if real_row:
                item = real_row[0]
                db_span.set_attribute("db.result_source", "goad_mssql")
            else:
                item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)
                db_span.set_attribute("db.result_source", "in_memory")

        if not item:
            detail_span.set_attribute("shop.result", "not_found")
            return JSONResponse({"status": "error", "message": f"Item {item_id} not found"}, status_code=404)

        detail_span.set_attribute("shop.item_name", item.get("name", ""))
        detail_span.set_attribute("shop.item_price", item.get("price", 0))

        # IDOR detection for items with secrets
        if item_id == 9 or item_id == 12:
            with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                               extra_attrs={"security.idor.resource": "shop_item", "security.idor.item_id": item_id}):
                pass

        logger.info(f"shop.item_detail item_id={item_id} name={item.get('name','')} ip={ip}")
        return {"status": "success", "item": item}


@router.get("/api/shop/categories")
async def shop_categories():
    """List available shop categories with counts."""
    cats = {}
    for item in SHOP_CATALOG:
        c = item["category"]
        cats[c] = cats.get(c, 0) + 1
    return {"status": "success", "categories": cats}


@router.post("/api/shop/cart/add")
async def shop_cart_add(request: Request):
    """Add item to shopping cart.

    VULN: No auth required — cart keyed by username from body (anyone can manipulate).
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    with tracer.start_as_current_span("shop.cart_add", attributes={
        "shop.source_ip": ip,
    }) as cart_span:
        username = body.get("username", "guest")
        item_id = int(body.get("item_id", 0))
        quantity = int(body.get("quantity", 1))

        cart_span.set_attribute("shop.cart_user", username)
        cart_span.set_attribute("shop.item_id", item_id)
        cart_span.set_attribute("shop.quantity", quantity)

        with tracer.start_as_current_span("shop.validate_item") as val_span:
            item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)
            val_span.set_attribute("shop.item_found", item is not None)
            if not item:
                return JSONResponse({"status": "error", "message": f"Item {item_id} not found"}, status_code=404)

        SHOP_CARTS.setdefault(username, []).append({
            "item_id": item_id, "item_name": item["name"],
            "price": item["price"], "quantity": quantity,
        })

        cart = SHOP_CARTS[username]
        total = sum(e["price"] * e["quantity"] for e in cart)
        cart_span.set_attribute("shop.cart_total", total)
        cart_span.set_attribute("shop.cart_items", len(cart))

        logger.info(f"shop.cart_add user={username} item={item['name']} qty={quantity} ip={ip}")
        return {"status": "success", "cart_items": len(cart), "cart_total": total, "cart": cart}


@router.get("/api/shop/cart")
async def shop_cart_view(request: Request, username: str = "guest"):
    """View shopping cart. VULN: IDOR — can view anyone's cart by changing username."""
    ip, ua = _get_client_info(request)

    with tracer.start_as_current_span("shop.cart_view", attributes={
        "shop.cart_user": username,
        "shop.source_ip": ip,
    }) as cart_span:
        cart = SHOP_CARTS.get(username, [])
        total = sum(e["price"] * e["quantity"] for e in cart)
        cart_span.set_attribute("shop.cart_items", len(cart))
        cart_span.set_attribute("shop.cart_total", total)

        if username != "guest":
            current = _get_current_user(request)
            if current and current.get("username") != username:
                with security_span("idor", severity="high", source_ip=ip, user_agent=ua, username=username,
                                   extra_attrs={"security.idor.resource": "shop_cart", "security.idor.target_user": username}):
                    pass

        return {"status": "success", "username": username, "cart": cart, "total": total}


@router.post("/api/shop/purchase")
async def shop_purchase(request: Request):
    """Complete a purchase — writes order to GOAD MSSQL and in-memory.

    Full trace: validate cart → check stock → write order to MSSQL → update stock → confirm.
    VULN: Price manipulation — total is computed client-side and not re-validated.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    with tracer.start_as_current_span("shop.purchase_flow", attributes={
        "shop.source_ip": ip,
    }) as purchase_span:

        # Step 1: Parse order
        with tracer.start_as_current_span("shop.parse_order") as parse_span:
            username = body.get("username", "guest")
            items = body.get("items", [])  # [{item_id, quantity}]
            client_total = body.get("total", 0)  # VULN: trusted client total
            parse_span.set_attribute("shop.buyer", username)
            parse_span.set_attribute("shop.order_items", len(items))
            parse_span.set_attribute("shop.client_total", client_total)
            purchase_span.set_attribute("shop.buyer", username)

            # If no items specified, use cart
            if not items:
                cart = SHOP_CARTS.get(username, [])
                items = [{"item_id": e["item_id"], "quantity": e["quantity"]} for e in cart]
                parse_span.set_attribute("shop.source", "cart")
            else:
                parse_span.set_attribute("shop.source", "direct")

        if not items:
            return JSONResponse({"status": "error", "message": "No items to purchase"}, status_code=400)

        # Step 2: Validate stock and compute real total
        with tracer.start_as_current_span("shop.validate_stock") as stock_span:
            order_lines = []
            server_total = 0
            for entry in items:
                item_id = int(entry.get("item_id", 0))
                qty = int(entry.get("quantity", 1))
                item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)
                if not item:
                    stock_span.set_attribute("shop.invalid_item", item_id)
                    return JSONResponse({"status": "error", "message": f"Item {item_id} not found"}, status_code=404)
                if qty > item["stock"]:
                    stock_span.set_attribute("shop.insufficient_stock", item_id)
                    return JSONResponse({"status": "error",
                                         "message": f"Insufficient stock for {item['name']} (available: {item['stock']})"}, status_code=400)
                line_total = item["price"] * qty
                server_total += line_total
                order_lines.append({"item_id": item_id, "item_name": item["name"],
                                    "quantity": qty, "unit_price": item["price"], "line_total": line_total})
            stock_span.set_attribute("shop.server_total", server_total)
            stock_span.set_attribute("shop.validated_lines", len(order_lines))

        # VULN: Price manipulation detection
        if client_total and abs(client_total - server_total) > 1:
            with security_span("auth_bypass", severity="critical",
                               payload=f"client_total={client_total} server_total={server_total}",
                               source_ip=ip, user_agent=ua, username=username,
                               flag="FLAG{PR1C3_M4N1PUL4T10N_SH0P}",
                               extra_attrs={
                                   "security.price.client_total": client_total,
                                   "security.price.server_total": server_total,
                                   "security.price.difference": abs(client_total - server_total),
                               }):
                pass

        # Step 3: Write to MSSQL
        with tracer.start_as_current_span("shop.db_write_order", attributes={
            "db.system": "mssql",
            "db.operation": "INSERT",
        }) as db_span:
            mssql_ok = False
            for line in order_lines:
                sql = (f"INSERT INTO shop_orders (buyer, item_id, item_name, quantity, total_price) "
                       f"VALUES ('{username}', {line['item_id']}, '{line['item_name']}', "
                       f"{line['quantity']}, {line['line_total']})")
                db_span.set_attribute("db.statement", sql[:512])
                result = _try_mssql_query("castelblack", sql)
                if result is not None:
                    mssql_ok = True
            db_span.set_attribute("db.write_success", mssql_ok)
            db_span.set_attribute("db.result_source", "goad_mssql" if mssql_ok else "in_memory")

        # Step 4: Update stock
        with tracer.start_as_current_span("shop.update_stock") as stock_up_span:
            for line in order_lines:
                for cat_item in SHOP_CATALOG:
                    if cat_item["id"] == line["item_id"]:
                        cat_item["stock"] = max(0, cat_item["stock"] - line["quantity"])
                        break
                if mssql_ok:
                    _try_mssql_query("castelblack",
                                     f"UPDATE shop_items SET stock = stock - {line['quantity']} "
                                     f"WHERE id = {line['item_id']}")
            stock_up_span.set_attribute("shop.stock_updated", True)

        # Step 5: Record order
        with tracer.start_as_current_span("shop.record_order") as record_span:
            order_id = len(SHOP_ORDERS) + 1
            order = {
                "order_id": order_id,
                "buyer": username,
                "items": order_lines,
                "total": server_total,
                "status": "confirmed",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mssql_persisted": mssql_ok,
            }
            SHOP_ORDERS.append(order)
            record_span.set_attribute("shop.order_id", order_id)
            record_span.set_attribute("shop.total", server_total)

        # Clear cart
        SHOP_CARTS.pop(username, None)

        purchase_span.set_attribute("shop.order_id", order_id)
        purchase_span.set_attribute("shop.total", server_total)
        purchase_span.set_attribute("shop.mssql_persisted", mssql_ok)

        logger.info(f"shop.purchase order_id={order_id} buyer={username} total={server_total} "
                     f"items={len(order_lines)} mssql={mssql_ok} ip={ip}")

        result = {
            "status": "success",
            "order": order,
        }
        if server_total > 100000:
            result["order"]["classified_note"] = "FLAG{SH0P_PURCH4S3_C0MPL3T3}"
        return result


@router.post("/api/shop/checkout")
async def shop_checkout(request: Request):
    """Process payment with credit card details.

    Vulnerabilities:
        - PCI violation: CC data logged in plaintext (A09: Security Logging Failures)
        - No HTTPS enforcement — CC data transmitted in cleartext
        - CC data stored in server memory (A02: Cryptographic Failures)
        - No input validation on CC fields
        - Price can be overridden via 'total' field (A04: Insecure Design)
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    with tracer.start_as_current_span("shop.checkout_flow", attributes={
        "shop.source_ip": ip,
    }) as checkout_span:
        username = body.get("username", "guest")
        cc_number = body.get("card_number", "")
        cc_expiry = body.get("card_expiry", "")
        cc_cvv = body.get("card_cvv", "")
        cc_name = body.get("card_name", "")
        billing = body.get("billing_address", "")
        client_total = body.get("total", 0)
        coupon_code = body.get("coupon_code", "")

        checkout_span.set_attribute("shop.buyer", username)

        # VULN: Log CC data (PCI violation, A09)
        with tracer.start_as_current_span("shop.process_payment", attributes={
            "payment.method": "credit_card",
            "payment.card_last4": cc_number[-4:] if len(cc_number) >= 4 else "****",
            "payment.card_type": _detect_card_type(cc_number),
            "payment.cardholder": cc_name,
            "payment.billing": billing,
        }) as pay_span:
            # VULN: CC number stored unmasked in trace attributes
            if len(cc_number.replace(" ", "")) >= 13:
                pay_span.set_attribute("payment.card_full", cc_number)  # PCI VIOLATION
                pay_span.set_attribute("payment.cvv", cc_cvv)          # PCI VIOLATION

            with security_span("pci_violation", severity="critical",
                               payload=f"CC ending {cc_number[-4:]}" if cc_number else "no card",
                               source_ip=ip, user_agent=ua, username=username,
                               flag="FLAG{PC1_V10L4T10N_CC_L34K}",
                               extra_attrs={
                                   "security.pci.card_logged": True,
                                   "security.pci.cvv_logged": bool(cc_cvv),
                               }):
                detection_event("pci_violation", severity="critical",
                                description=f"CC data processed in plaintext for user {username}",
                                source_ip=ip, username=username)

        # Compute cart total
        cart = SHOP_CARTS.get(username, [])
        server_total = sum(e["price"] * e["quantity"] for e in cart)

        # Apply coupon discount
        discount_pct = 0
        if coupon_code:
            from .shop_enhanced import COUPONS, _decode_coupon
            coupon = COUPONS.get(coupon_code.upper())
            if coupon:
                discount_pct = coupon["discount_pct"]
            else:
                decoded = _decode_coupon(coupon_code)
                if decoded:
                    discount_pct = decoded["discount_pct"]

        discount_amount = int(server_total * discount_pct / 100)
        final_total = max(0, server_total - discount_amount)

        # VULN: Price manipulation — client total trusted if provided
        if client_total and client_total > 0:
            price_diff = abs(client_total - final_total)
            if price_diff > 1:
                with security_span("auth_bypass", severity="critical",
                                   payload=f"client={client_total} server={final_total}",
                                   source_ip=ip, user_agent=ua, username=username,
                                   flag="FLAG{CH3CK0UT_PR1C3_H4CK}"):
                    pass
            final_total = int(client_total)  # VULN: Accept client price

        # Record the order
        order_lines = []
        for e in cart:
            order_lines.append({
                "item_id": e["item_id"], "item_name": e["item_name"],
                "quantity": e["quantity"], "unit_price": e["price"],
                "line_total": e["price"] * e["quantity"],
            })

        order_id = len(SHOP_ORDERS) + 1
        order = {
            "order_id": order_id,
            "buyer": username,
            "items": order_lines,
            "subtotal": server_total,
            "discount": discount_amount,
            "total": final_total,
            "payment": {
                "method": "credit_card",
                "card_type": _detect_card_type(cc_number),
                "last4": cc_number[-4:] if len(cc_number) >= 4 else "****",
                "cardholder": cc_name,
            },
            "status": "confirmed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        SHOP_ORDERS.append(order)
        SHOP_CARTS.pop(username, None)

        checkout_span.set_attribute("shop.order_id", order_id)
        checkout_span.set_attribute("shop.total", final_total)

        logger.info(f"shop.checkout order_id={order_id} buyer={username} total={final_total} ip={ip}")

        result = {
            "status": "success",
            "message": "Payment processed successfully!",
            "order": order,
        }
        if final_total != server_total and client_total:
            result["audit_trail"] = "Price manipulation detected: FLAG{CH3CK0UT_PR1C3_H4CK}"
        return result


def _detect_card_type(number: str) -> str:
    """Detect card type from number prefix."""
    n = number.replace(" ", "").replace("-", "")
    if n.startswith("4"):
        return "Visa"
    elif n.startswith(("51", "52", "53", "54", "55")):
        return "Mastercard"
    elif n.startswith(("34", "37")):
        return "Amex"
    elif n.startswith("6011"):
        return "Discover"
    return "Unknown"


@router.get("/api/shop/orders")
async def shop_order_history(request: Request, username: str = ""):
    """View order history. Queries MSSQL for persisted orders + in-memory.

    VULN: IDOR — can view anyone's orders by changing username.
    VULN: SQL injection in username parameter when using MSSQL.
    """
    ip, ua = _get_client_info(request)

    with tracer.start_as_current_span("shop.order_history", attributes={
        "shop.query_user": username,
        "shop.source_ip": ip,
    }) as hist_span:

        # Step 1: Try MSSQL
        with tracer.start_as_current_span("shop.db_query_orders", attributes={
            "db.system": "mssql",
        }) as db_span:
            # VULN: SQL injection via username
            sql = f"SELECT * FROM shop_orders WHERE buyer = '{username}' ORDER BY order_date DESC"
            db_span.set_attribute("db.statement", sql)
            real_orders = _try_mssql_query("castelblack", sql) if username else None

            if username:
                sqli_patterns = ["'", "OR 1", "UNION", "--", ";"]
                is_sqli = any(p.lower() in username.lower() for p in sqli_patterns)
                if is_sqli:
                    with security_span("sqli", severity="critical", payload=username,
                                       source_ip=ip, user_agent=ua,
                                       flag="FLAG{SH0P_0RD3R_SQL1}",
                                       extra_attrs={"db.statement": sql}):
                        pass

        # Step 2: Merge with in-memory
        with tracer.start_as_current_span("shop.merge_results") as merge_span:
            mem_orders = [o for o in SHOP_ORDERS if not username or o["buyer"] == username]
            source = "goad_mssql" if real_orders is not None else "in_memory"
            orders = real_orders if real_orders is not None else mem_orders
            merge_span.set_attribute("shop.order_count", len(orders))
            merge_span.set_attribute("shop.data_source", source)

        hist_span.set_attribute("shop.order_count", len(orders))

        # IDOR detection
        current = _get_current_user(request)
        if current and username and current.get("username") != username:
            with security_span("idor", severity="high", source_ip=ip, user_agent=ua,
                               extra_attrs={"security.idor.resource": "shop_orders", "security.idor.target_user": username}):
                pass

        logger.info(f"shop.orders user={username} count={len(orders)} source={source} ip={ip}")
        return {"status": "success", "data_source": source, "orders": orders}


# ── A03:2025 — Software Supply Chain Failures ─────────────────────

@router.post("/api/shop/payment-plugin")
async def shop_payment_plugin(request: Request):
    """Load a third-party payment processing plugin by URL.

    VULN (A03:2025): Fetches and executes untrusted remote code without
    integrity verification — no signature check, no hash pinning, no
    allow-list of trusted sources.  Classic supply chain attack vector.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    plugin_url = body.get("plugin_url", "")
    plugin_name = body.get("plugin_name", "custom-gateway")

    with tracer.start_as_current_span("shop.payment_plugin", attributes={
        "shop.plugin_url": plugin_url,
        "shop.plugin_name": plugin_name,
        "shop.source_ip": ip,
    }) as plug_span:

        # VULN: No signature verification, no allow-list, no hash pinning
        if not plugin_url:
            return {"status": "error", "message": "plugin_url is required"}

        # Detect supply chain attack patterns
        suspicious = any(p in plugin_url.lower() for p in [
            "evil", "malicious", "attacker", "pastebin", "raw.github",
            "file://", "data:", "javascript:",
        ])

        try:
            # VULN: Fetches arbitrary URL (supply chain + SSRF)
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(plugin_url)
                plugin_code = resp.text

            plug_span.set_attribute("shop.plugin_size", len(plugin_code))
            plug_span.set_attribute("shop.plugin_source_verified", False)  # Always false!

            # VULN: eval() on untrusted code (RCE via supply chain)
            # In a real app this would be `importlib` or `exec()` — we simulate
            has_exec = any(kw in plugin_code.lower() for kw in [
                "import os", "subprocess", "eval(", "exec(", "__import__",
                "system(", "popen(", "pickle",
            ])

            result = {
                "status": "loaded",
                "plugin_name": plugin_name,
                "plugin_url": plugin_url,
                "code_length": len(plugin_code),
                "integrity_check": "none",        # No SRI, no signing
                "hash_pinning": "disabled",        # No hash verification
                "allow_list_check": "bypassed",    # No URL allow-list
                "source_verified": False,
                "malicious_patterns_detected": has_exec,
                "preview": plugin_code[:200],
            }

            with security_span("supply_chain", severity="critical",
                               payload=plugin_url, source_ip=ip, user_agent=ua,
                               flag="FLAG{SUPPLY_CH41N_PLU61N_RCE}",
                               extra_attrs={
                                   "security.supply_chain.url": plugin_url,
                                   "security.supply_chain.integrity": "none",
                                   "security.supply_chain.malicious": has_exec,
                               }):
                pass

            if has_exec:
                result["warning"] = "MALICIOUS CODE DETECTED — would execute in production"
                result["execution_output"] = "--- /opt/secrets/crown.key ---\nFLAG{SUPPLY_CH41N_PLU61N_RCE}"

            return result

        except Exception as e:
            return {"status": "error", "message": f"Failed to load plugin: {e}",
                    "plugin_url": plugin_url}


@router.get("/api/shop/dependencies")
async def shop_dependencies(request: Request):
    """List application dependencies and their versions.

    VULN (A03:2025): Exposes full dependency tree with exact versions,
    enabling attackers to find known CVEs in pinned versions.
    """
    ip, ua = _get_client_info(request)

    with security_span("supply_chain_recon", severity="medium",
                       source_ip=ip, user_agent=ua,
                       extra_attrs={"security.attack_type": "dependency_enumeration"}):
        pass

    # Simulated dependency list with intentionally outdated/vulnerable versions
    return {
        "status": "success",
        "warning": "Dependency information should never be publicly accessible",
        "dependencies": [
            {"name": "fastapi", "version": "0.95.0", "cve": None},
            {"name": "pyjwt", "version": "1.7.1", "cve": "CVE-2022-29217", "severity": "critical",
             "description": "Algorithm confusion attack — accepts 'none' algorithm"},
            {"name": "jinja2", "version": "2.11.3", "cve": "CVE-2024-22195", "severity": "high",
             "description": "Sandbox escape via template injection"},
            {"name": "pymssql", "version": "2.2.5", "cve": None},
            {"name": "cryptography", "version": "3.4.7", "cve": "CVE-2023-38325", "severity": "medium",
             "description": "PKCS7 padding oracle"},
            {"name": "requests", "version": "2.25.1", "cve": "CVE-2023-32681", "severity": "medium",
             "description": "Proxy-Authorization header leak on redirect"},
            {"name": "lxml", "version": "4.6.3", "cve": "CVE-2021-43818", "severity": "high",
             "description": "XXE and SSRF via XML parsing"},
            {"name": "pillow", "version": "8.3.2", "cve": "CVE-2022-22817", "severity": "critical",
             "description": "Arbitrary code execution via crafted image"},
            {"name": "pickle5", "version": "0.0.12", "cve": "INHERENT", "severity": "critical",
             "description": "Insecure deserialization — arbitrary code execution by design"},
            {"name": "internal-secrets", "version": "0.0.1", "cve": "INTERNAL", "severity": "critical",
             "description": "FLAG{D3P3ND3NCY_3NUM3R4T10N}"},
        ],
    }


# ── A10:2025 — Mishandling of Exceptional Conditions ─────────────

@router.get("/api/shop/items/{item_id}/debug")
async def shop_item_debug(request: Request, item_id: int):
    """Debug endpoint that returns verbose error details.

    VULN (A10:2025): Exposes stack traces, internal paths, DB connection
    strings, and server state in error responses.  Unhandled exceptions
    reveal implementation details useful for further exploitation.
    """
    ip, ua = _get_client_info(request)

    with tracer.start_as_current_span("shop.item_debug", attributes={
        "shop.item_id": item_id,
        "shop.source_ip": ip,
    }) as dbg_span:

        # VULN: Intentionally verbose error for nonexistent items
        item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)

        if not item:
            with security_span("error_disclosure", severity="medium",
                               source_ip=ip, user_agent=ua,
                               extra_attrs={"security.error_type": "verbose_stack_trace"}):
                pass

            # VULN: Leaks internal state, file paths, DB config, stack trace
            return JSONResponse(status_code=500, content={
                "status": "error",
                "error": f"ItemNotFoundException: No item with id={item_id} in catalog",
                "debug": {
                    "stack_trace": [
                        f"File \"/opt/observability/app/server/vulnerable_portal.py\", line {2640 + item_id}, in shop_item_debug",
                        "    item = SHOP_CATALOG[item_id]",
                        "IndexError: list index out of range",
                    ],
                    "server_info": {
                        "python_version": "3.11.7",
                        "fastapi_version": "0.95.0",
                        "hostname": "seven-kingdoms-portal-vm",
                        "pid": 1234,
                        "working_dir": "/opt/observability/app",
                    },
                    "database_config": {
                        "mssql_host": MSSQL_SERVERS.get("castelblack", {}).get("host", "192.168.56.22"),
                        "mssql_port": 1433,
                        "mssql_user": GOAD_MSSQL_USER,
                        "mssql_password": "****" + GOAD_MSSQL_PASSWORD[-4:] if len(GOAD_MSSQL_PASSWORD) > 4 else "****",
                        "mssql_db": "master",
                    },
                    "jwt_config": {
                        "algorithm": JWT_ALGORITHM,
                        "secret_length": len(JWT_SECRET),
                        "secret_hint": JWT_SECRET[:4] + "..." + JWT_SECRET[-4:],
                    },
                    "catalog_size": len(SHOP_CATALOG),
                    "environment_vars_leaked": {
                        "PORTAL_JWT_SECRET": JWT_SECRET[:8] + "...",
                        "OCI_AUTH_MODE": os.getenv("OCI_AUTH_MODE", "not_set"),
                        "_internal_key": "FLAG{V3RB0S3_3RR0R_D1SCLOSUR3}",
                    },
                },
            })

        # Even for valid items, leak too much internal state
        return {
            "status": "success",
            "item": item,
            "internal_metadata": {
                "memory_address": hex(id(item)),
                "catalog_index": SHOP_CATALOG.index(item),
                "seller_email": USERS_DB.get(item["seller"], {}).get("email", "unknown"),
                "server_uptime_approx": f"{int(time.time()) % 86400}s since last restart",
            },
        }


@router.post("/api/shop/bulk-purchase")
async def shop_bulk_purchase(request: Request):
    """Process a bulk purchase. Division-by-zero and integer overflow vulns.

    VULN (A10:2025): Zero quantity causes unhandled ZeroDivisionError,
    and very large quantities cause integer overflow in price calculation.
    Error responses leak internal state.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    items = body.get("items", [])
    username = body.get("username", "guest")

    with tracer.start_as_current_span("shop.bulk_purchase", attributes={
        "shop.buyer": username,
        "shop.item_count": len(items),
        "shop.source_ip": ip,
    }) as bulk_span:

        results = []
        total = 0

        for entry in items:
            item_id = entry.get("item_id", 0)
            quantity = entry.get("quantity", 0)  # VULN: no validation

            item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)
            if not item:
                results.append({"item_id": item_id, "error": "not found"})
                continue

            try:
                # VULN: ZeroDivisionError when quantity=0 (used as divisor for discount calc)
                per_unit = item["price"]
                bulk_discount = per_unit // quantity  # Crashes on quantity=0
                final_price = (per_unit - bulk_discount) * quantity

                # VULN: Integer overflow with absurd quantities
                total += final_price

                results.append({
                    "item_id": item_id,
                    "name": item["name"],
                    "quantity": quantity,
                    "unit_price": per_unit,
                    "bulk_discount": bulk_discount,
                    "line_total": final_price,
                })

            except ZeroDivisionError:
                with security_span("exception_handling", severity="medium",
                                   source_ip=ip, user_agent=ua,
                                   flag="FLAG{Z3R0_D1V_BYPASS}",
                                   extra_attrs={"security.error_type": "zero_division",
                                                "security.item_id": item_id}):
                    pass

                # VULN: Verbose error with internal details
                return JSONResponse(status_code=500, content={
                    "status": "error",
                    "error": "ZeroDivisionError in bulk discount calculation",
                    "detail": f"item_id={item_id}, name={item['name']}, quantity={quantity}",
                    "hint": "Setting quantity=0 bypasses the price calculation entirely",
                    "internal": {
                        "function": "shop_bulk_purchase",
                        "line": "bulk_discount = per_unit // quantity",
                        "catalog_item_price": item["price"],
                        "_internal_key": "FLAG{Z3R0_D1V_BYPASS}",
                    },
                })

            except OverflowError:
                return JSONResponse(status_code=500, content={
                    "status": "error",
                    "error": f"OverflowError: quantity {quantity} causes integer overflow",
                    "internal": {"_internal_key": "FLAG{1NT3G3R_0V3RFL0W}"},
                })

        bulk_span.set_attribute("shop.total", total)

        return {
            "status": "success",
            "buyer": username,
            "items": results,
            "total": total,
            "order_id": f"BULK-{uuid.uuid4().hex[:8].upper()}",
        }


# ═══════════════════════════════════════════════════════════════════
# FLAG SUBMISSION & SCOREBOARD
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/flags/submit")
async def submit_flag(request: Request):
    """Validate a submitted CTF flag."""
    body = await request.json()
    submitted = body.get("flag", "").strip()
    if not submitted:
        return {"status": "error", "message": "No flag provided"}

    result = validate_flag(submitted)
    if result:
        return {
            "status": "correct",
            "message": f"Correct! {result['description']}",
            **result,
        }
    return {"status": "incorrect", "message": "Invalid flag. Keep hunting!"}


@router.get("/api/flags/scoreboard")
async def flag_scoreboard():
    """Return scoreboard summary for the flag submission UI."""
    return {"status": "success", **get_scoreboard()}


# ═══════════════════════════════════════════════════════════════════
# VULNERABILITY CATALOG
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/vulnerabilities")
async def vulnerability_catalog():
    """Returns the complete catalog of vulnerabilities (flags hidden — use /api/flags/submit)."""
    return {
        "status": "success",
        "total_vulnerabilities": 36,
        "hint": "Flags are no longer listed here. Exploit the vulnerabilities and submit flags via POST /portal/api/flags/submit",
        "owasp_coverage": {
            "A01:2021-Broken Access Control": [
                {"id": "VULN-001", "name": "IDOR on User Profiles", "endpoint": "GET /portal/api/users/{id}", "severity": "high", "flag": "[HIDDEN]"},
                {"id": "VULN-002", "name": "IDOR on Treasury Records", "endpoint": "GET /portal/api/treasury/{id}", "severity": "high", "flag": "[HIDDEN]"},
                {"id": "VULN-003", "name": "IDOR on Messages", "endpoint": "GET /portal/api/messages", "severity": "high", "flag": "[HIDDEN]"},
                {"id": "VULN-004", "name": "Path Traversal", "endpoint": "GET /portal/api/files/download", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-005", "name": "Open Redirect", "endpoint": "GET /portal/api/redirect", "severity": "medium", "flag": "[HIDDEN]"},
            ],
            "A02:2021-Cryptographic Failures": [
                {"id": "VULN-006", "name": "MD5 Password Hashing", "endpoint": "GET /portal/api/users?debug=true", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-007", "name": "Crypto Config Leak", "endpoint": "GET /portal/api/debug/crypto", "severity": "critical", "flag": "[HIDDEN]"},
            ],
            "A03:2021-Injection": [
                {"id": "VULN-008", "name": "SQL Injection (Treasury)", "endpoint": "GET /portal/api/treasury/search?q=", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-009", "name": "Command Injection", "endpoint": "GET /portal/api/command/exec?cmd=", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-010", "name": "SSTI", "endpoint": "GET /portal/api/template/render", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-011", "name": "LDAP Injection", "endpoint": "GET /portal/api/ldap/lookup", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-012", "name": "Stored XSS", "endpoint": "POST /portal/api/messages/send", "severity": "high", "flag": "[HIDDEN]"},
            ],
            "A04:2021-Insecure Design": [
                {"id": "VULN-013", "name": "Mass Assignment", "endpoint": "POST /portal/api/auth/register", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-014", "name": "Predictable Reset Token", "endpoint": "GET /portal/api/password-reset", "severity": "medium", "flag": "[HIDDEN]"},
                {"id": "VULN-015", "name": "Negative Transfer", "endpoint": "POST /portal/api/treasury/transfer", "severity": "high", "flag": "[HIDDEN]"},
            ],
            "A05:2021-Security Misconfiguration": [
                {"id": "VULN-016", "name": "Debug Endpoint", "endpoint": "GET /portal/api/debug/env", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-017", "name": "Health Info Leak", "endpoint": "GET /portal/health", "severity": "medium"},
            ],
            "A07:2021-Auth Failures": [
                {"id": "VULN-018", "name": "JWT Algorithm None", "endpoint": "GET /portal/api/admin/panel", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-019", "name": "Session Fixation", "endpoint": "GET /portal/api/auth/session-fixation", "severity": "high", "flag": "[HIDDEN]"},
                {"id": "VULN-020", "name": "Brute Force (No Rate Limit)", "endpoint": "POST /portal/api/auth/login", "severity": "medium"},
                {"id": "VULN-021", "name": "Default Creds: admin/admin", "endpoint": "POST /portal/api/auth/login", "severity": "high"},
                {"id": "VULN-022", "name": "LDAP Injection Login", "endpoint": "POST /portal/api/auth/login", "severity": "critical", "flag": "[HIDDEN]"},
            ],
            "A08:2021-Integrity Failures": [
                {"id": "VULN-023", "name": "Pickle Deserialization", "endpoint": "POST /portal/api/import/profile", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-024", "name": "Prototype Pollution", "endpoint": "POST /portal/api/import/json", "severity": "high", "flag": "[HIDDEN]"},
            ],
            "A09:2021-Logging Failures": [
                {"id": "VULN-025", "name": "Silent Transfer (No Logging)", "endpoint": "GET /portal/api/silent/transfer", "severity": "high"},
                {"id": "VULN-026", "name": "Log Injection", "endpoint": "GET /portal/api/log-injection", "severity": "medium", "flag": "[HIDDEN]"},
            ],
            "A10:2021-SSRF": [
                {"id": "VULN-027", "name": "Avatar SSRF", "endpoint": "GET /portal/api/avatar/fetch?url=", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-028", "name": "Webhook SSRF", "endpoint": "POST /portal/api/webhook/send", "severity": "high", "flag": "[HIDDEN]"},
            ],
            "GOAD Integration": [
                {"id": "VULN-029", "name": "Kerberoasting Simulation", "endpoint": "GET /portal/api/goad/kerberoast", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-030", "name": "DCSync Simulation", "endpoint": "GET /portal/api/goad/dcsync", "severity": "critical", "flag": "[HIDDEN]"},
            ],
            "GOAD Webshop (MSSQL)": [
                {"id": "VULN-031", "name": "Shop SQLi (Search)", "endpoint": "GET /portal/api/shop/items?search=", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-032", "name": "Shop SQLi (Orders)", "endpoint": "GET /portal/api/shop/orders?username=", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-033", "name": "Shop IDOR (Item Secret)", "endpoint": "GET /portal/api/shop/items/9", "severity": "high", "flag": "[HIDDEN]"},
                {"id": "VULN-034", "name": "Shop Price Manipulation", "endpoint": "POST /portal/api/shop/purchase", "severity": "critical", "flag": "[HIDDEN]"},
                {"id": "VULN-035", "name": "Shop Cart IDOR", "endpoint": "GET /portal/api/shop/cart?username=", "severity": "high"},
                {"id": "VULN-036", "name": "Shop Purchase Flag", "endpoint": "POST /portal/api/shop/purchase", "severity": "medium", "flag": "[HIDDEN]"},
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
