"""OpenTelemetry Security Span Enrichment for Vulnerability Detection.

Every attack against the vulnerable portal generates spans with standardized
security.* attributes.  OCI APM Trace Explorer and Log Analytics can query
these attributes to build detection rules, e.g.:

    SpanAttribute[security.attack.detected] = 'true'
    AND SpanAttribute[security.attack.severity] IN ('critical','high')

Attributes follow a consistent schema so that a single Log Analytics saved
search can catch *any* newly added vulnerability type.
"""
from __future__ import annotations

import functools
import os
import time
from typing import Any

from opentelemetry import trace

tracer = trace.get_tracer("security.vulnerability")

# Runtime context — injected into every security span for APM filtering
_RUNTIME = os.getenv("APP_RUNTIME", "unknown").strip().lower()
_SERVICE = os.getenv("APP_SERVICE_NAME", f"seven-kingdoms-portal-{_RUNTIME}")


# ── MITRE ATT&CK mapping for each vulnerability class ──────────────
MITRE_MAP: dict[str, dict[str, str]] = {
    "sqli":             {"id": "T1190", "tactic": "initial-access", "name": "Exploit Public-Facing Application"},
    "xss":              {"id": "T1059.007", "tactic": "execution", "name": "JavaScript Execution"},
    "ssti":             {"id": "T1059", "tactic": "execution", "name": "Command and Scripting Interpreter"},
    "lfi":              {"id": "T1005", "tactic": "collection", "name": "Data from Local System"},
    "rce":              {"id": "T1059", "tactic": "execution", "name": "Command and Scripting Interpreter"},
    "ssrf":             {"id": "T1090", "tactic": "command-and-control", "name": "Proxy"},
    "idor":             {"id": "T1078", "tactic": "privilege-escalation", "name": "Valid Accounts"},
    "auth_bypass":      {"id": "T1078", "tactic": "defense-evasion", "name": "Valid Accounts"},
    "jwt_manipulation": {"id": "T1134", "tactic": "privilege-escalation", "name": "Access Token Manipulation"},
    "ldap_injection":   {"id": "T1190", "tactic": "initial-access", "name": "Exploit Public-Facing Application"},
    "xxe":              {"id": "T1190", "tactic": "initial-access", "name": "Exploit Public-Facing Application"},
    "deserialization":  {"id": "T1059", "tactic": "execution", "name": "Command and Scripting Interpreter"},
    "path_traversal":   {"id": "T1083", "tactic": "discovery", "name": "File and Directory Discovery"},
    "priv_escalation":  {"id": "T1068", "tactic": "privilege-escalation", "name": "Exploitation for Privilege Escalation"},
    "credential_leak":  {"id": "T1552", "tactic": "credential-access", "name": "Unsecured Credentials"},
    "brute_force":      {"id": "T1110", "tactic": "credential-access", "name": "Brute Force"},
    "log_injection":    {"id": "T1070", "tactic": "defense-evasion", "name": "Indicator Removal"},
    "mass_assignment":  {"id": "T1098", "tactic": "persistence", "name": "Account Manipulation"},
    "csrf":             {"id": "T1185", "tactic": "collection", "name": "Browser Session Hijacking"},
    "open_redirect":    {"id": "T1566.002", "tactic": "initial-access", "name": "Phishing: Spearphishing Link"},
    "exfiltration":     {"id": "T1041", "tactic": "exfiltration", "name": "Exfiltration Over C2 Channel"},
    "persistence":      {"id": "T1543", "tactic": "persistence", "name": "Create or Modify System Process"},
    # Enhanced marketplace (Juice Shop-inspired)
    "forged_identity":         {"id": "T1078", "tactic": "defense-evasion", "name": "Valid Accounts"},
    "stored_xss":              {"id": "T1059.007", "tactic": "execution", "name": "JavaScript Execution"},
    "coupon_forge":            {"id": "T1565", "tactic": "impact", "name": "Data Manipulation"},
    "expired_coupon":          {"id": "T1565", "tactic": "impact", "name": "Data Manipulation"},
    "negative_transfer":       {"id": "T1565.002", "tactic": "impact", "name": "Transmitted Data Manipulation"},
    "negative_quantity":       {"id": "T1565.002", "tactic": "impact", "name": "Transmitted Data Manipulation"},
    "price_tampering":         {"id": "T1565.002", "tactic": "impact", "name": "Transmitted Data Manipulation"},
    "captcha_bypass":          {"id": "T1185", "tactic": "collection", "name": "Browser Session Hijacking"},
    "score_board_discovery":   {"id": "T1083", "tactic": "discovery", "name": "File and Directory Discovery"},
    "hidden_endpoint":         {"id": "T1083", "tactic": "discovery", "name": "File and Directory Discovery"},
    "admin_panel_access":      {"id": "T1078", "tactic": "defense-evasion", "name": "Valid Accounts"},
    "admin_panel":             {"id": "T1078", "tactic": "defense-evasion", "name": "Valid Accounts"},
    "security_question_bypass": {"id": "T1110.001", "tactic": "credential-access", "name": "Password Guessing"},
    "password_reset_osint":    {"id": "T1110.001", "tactic": "credential-access", "name": "Password Guessing"},
    "privilege_escalation":    {"id": "T1068", "tactic": "privilege-escalation", "name": "Exploitation for Privilege Escalation"},
    "prototype_pollution":     {"id": "T1059", "tactic": "execution", "name": "Command and Scripting Interpreter"},
    # GOAD AD attack techniques
    "kerberoasting":           {"id": "T1558.003", "tactic": "credential-access", "name": "Kerberoasting"},
    "dcsync":                  {"id": "T1003.006", "tactic": "credential-access", "name": "OS Credential Dumping: DCSync"},
    # Caldera / red-team attack simulation
    "lateral_movement":        {"id": "T1021", "tactic": "lateral-movement", "name": "Remote Services"},
    "data_collection":         {"id": "T1560", "tactic": "collection", "name": "Archive Collected Data"},
    "internal_recon":          {"id": "T1046", "tactic": "discovery", "name": "Network Service Discovery"},
    "c2_exfiltration":         {"id": "T1041", "tactic": "exfiltration", "name": "Exfiltration Over C2 Channel"},
    "service_persistence":     {"id": "T1543", "tactic": "persistence", "name": "Create or Modify System Process"},
}

# OWASP Top 10 (2021) mapping
OWASP_MAP: dict[str, str] = {
    "sqli": "A03:2021-Injection",
    "xss": "A03:2021-Injection",
    "ssti": "A03:2021-Injection",
    "lfi": "A01:2021-Broken Access Control",
    "rce": "A03:2021-Injection",
    "ssrf": "A10:2021-SSRF",
    "idor": "A01:2021-Broken Access Control",
    "auth_bypass": "A07:2021-Auth Failures",
    "jwt_manipulation": "A07:2021-Auth Failures",
    "ldap_injection": "A03:2021-Injection",
    "xxe": "A05:2021-Security Misconfiguration",
    "deserialization": "A08:2021-Integrity Failures",
    "path_traversal": "A01:2021-Broken Access Control",
    "priv_escalation": "A01:2021-Broken Access Control",
    "credential_leak": "A02:2021-Cryptographic Failures",
    "brute_force": "A07:2021-Auth Failures",
    "log_injection": "A09:2021-Logging Failures",
    "mass_assignment": "A04:2021-Insecure Design",
    "csrf": "A01:2021-Broken Access Control",
    "open_redirect": "A01:2021-Broken Access Control",
    "exfiltration": "A01:2021-Broken Access Control",
    "persistence": "A05:2021-Security Misconfiguration",
    # Enhanced marketplace (Juice Shop-inspired)
    "forged_identity": "A01:2021-Broken Access Control",
    "stored_xss": "A03:2021-Injection",
    "coupon_forge": "A02:2021-Cryptographic Failures",
    "expired_coupon": "A04:2021-Insecure Design",
    "negative_transfer": "A04:2021-Insecure Design",
    "negative_quantity": "A04:2021-Insecure Design",
    "price_tampering": "A04:2021-Insecure Design",
    "captcha_bypass": "A07:2021-Auth Failures",
    "score_board_discovery": "A05:2021-Security Misconfiguration",
    "hidden_endpoint": "A05:2021-Security Misconfiguration",
    "admin_panel_access": "A01:2021-Broken Access Control",
    "admin_panel": "A01:2021-Broken Access Control",
    "security_question_bypass": "A07:2021-Auth Failures",
    "password_reset_osint": "A07:2021-Auth Failures",
    "privilege_escalation": "A01:2021-Broken Access Control",
    "prototype_pollution": "A03:2021-Injection",
    # GOAD AD attack techniques (no OWASP category — OS-level)
    "kerberoasting": "N/A",
    "dcsync": "N/A",
    # Caldera / red-team attack simulation
    "lateral_movement": "N/A",
    "data_collection": "N/A",
    "internal_recon": "N/A",
    "c2_exfiltration": "A01:2021-Broken Access Control",
    "service_persistence": "A05:2021-Security Misconfiguration",
}


def security_span(
    vuln_type: str,
    *,
    severity: str = "high",
    payload: str = "",
    source_ip: str = "",
    user_agent: str = "",
    username: str = "",
    flag: str = "",
    extra_attrs: dict[str, Any] | None = None,
) -> trace.Span:
    """Start a span enriched with security detection attributes.

    Returns an *active* span (used as a context manager):

        with security_span("sqli", severity="critical", payload=q) as span:
            # ... do vulnerable thing ...

    The span carries attributes that OCI APM / Log Analytics can query:
        security.attack.detected        = true
        security.attack.type            = sqli
        security.attack.severity        = critical
        security.attack.mitre_id        = T1190
        security.attack.mitre_tactic    = initial-access
        security.attack.owasp           = A03:2021-Injection
        security.attack.payload         = <first 512 chars>
        security.attack.flag            = FLAG{...}
        security.source_ip              = 1.2.3.4
        security.user_agent             = ...
        security.username               = jon.snow
    """
    mitre = MITRE_MAP.get(vuln_type, {"id": "T1190", "tactic": "unknown", "name": "Unknown"})
    owasp = OWASP_MAP.get(vuln_type, "Unknown")

    attrs: dict[str, Any] = {
        "security.attack.detected": True,
        "security.attack.type": vuln_type,
        "security.attack.severity": severity,
        "security.attack.mitre_id": mitre["id"],
        "security.attack.mitre_tactic": mitre["tactic"],
        "security.attack.mitre_name": mitre["name"],
        "security.attack.owasp": owasp,
        "security.attack.timestamp": time.time(),
        "app.runtime": _RUNTIME,
        "app.service": _SERVICE,
    }

    if payload:
        attrs["security.attack.payload"] = payload[:512]
    if source_ip:
        attrs["security.source_ip"] = source_ip
    if user_agent:
        attrs["security.user_agent"] = user_agent[:256]
    if username:
        attrs["security.username"] = username
    if flag:
        attrs["security.flag.captured"] = True
        attrs["security.flag.id"] = flag

    if extra_attrs:
        attrs.update(extra_attrs)

    span_name = f"ATTACK:{vuln_type.upper()}"
    return tracer.start_as_current_span(span_name, attributes=attrs)


def detection_event(
    vuln_type: str,
    *,
    severity: str = "high",
    description: str = "",
    payload: str = "",
    source_ip: str = "",
    username: str = "",
) -> None:
    """Record a security event as a standalone span (fire-and-forget).

    Useful when you want to log a detection without wrapping a code block.
    """
    mitre = MITRE_MAP.get(vuln_type, {"id": "T1190", "tactic": "unknown", "name": "Unknown"})
    with tracer.start_as_current_span(
        f"DETECTION:{vuln_type.upper()}",
        attributes={
            "security.event.type": "detection",
            "security.attack.detected": True,
            "security.attack.type": vuln_type,
            "security.attack.severity": severity,
            "security.attack.mitre_id": mitre["id"],
            "security.attack.mitre_tactic": mitre["tactic"],
            "security.attack.description": description[:1024],
            "security.attack.payload": payload[:512],
            "security.source_ip": source_ip,
            "security.username": username,
            "app.runtime": _RUNTIME,
            "app.service": _SERVICE,
        },
    ):
        pass
