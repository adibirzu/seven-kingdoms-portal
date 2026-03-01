"""Seven Kingdoms Portal — Enhanced Marketplace & Additional Vulnerabilities.

Juice Shop-inspired vulnerability endpoints mapped to the GOAD theme:
  - Product Reviews: stored XSS, forged identity (submit as other user)
  - Coupon System: weak encoding (base64), expired coupon reuse
  - Gold Wallet: negative quantity, race condition on transfers
  - Trade Import: XXE via XML parsing
  - Allegiance Change: CSRF (no token validation)
  - Security Question Reset: OSINT-exploitable GoT trivia
  - Admin Registration: hidden role parameter escalation
  - Score Board: hidden discovery challenge
  - Anti-Automation: CAPTCHA bypass on feedback
  - Prototype Pollution: deep merge on config update

All endpoints generate OTel spans with security.* attributes for
detection rule correlation in OCI APM and Log Analytics.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import struct
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any
from xml.etree import ElementTree

import pymssql
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from opentelemetry import trace

from .otel_security import security_span, detection_event
from .vulnerable_portal import (
    _get_client_info, _verify_jwt, _get_current_user, _lookup_user,
    _create_jwt, _save_user_to_shared_store,
    USERS_DB, SESSIONS, SHOP_CATALOG, SHOP_ORDERS, SHOP_CARTS,
    MSSQL_SERVERS, GOAD_MSSQL_USER, GOAD_MSSQL_PASSWORD,
    JWT_SECRET, DELETED_PRODUCTS,
)

logger = logging.getLogger("Portal.Enhanced")
tracer = trace.get_tracer("portal.enhanced")

router = APIRouter(prefix="/portal", tags=["Enhanced Marketplace"])


# ═══════════════════════════════════════════════════════════════════
# DATA STORES
# ═══════════════════════════════════════════════════════════════════

# Product reviews — intentionally allows XSS and identity forging
PRODUCT_REVIEWS: list[dict] = [
    {"id": 1, "item_id": 1, "author": "jon.snow", "rating": 5,
     "comment": "Ice served House Stark for generations. Best sword in Westeros.",
     "timestamp": "2024-01-10T08:00:00Z"},
    {"id": 2, "item_id": 3, "author": "tyrion.lannister", "rating": 2,
     "comment": "Wildfire is effective but too dangerous. My sister should not have access to this.",
     "timestamp": "2024-01-12T14:30:00Z"},
    {"id": 3, "item_id": 6, "author": "daenerys.targaryen", "rating": 5,
     "comment": "The Dothraki stallion reminds me of Khal Drogo's mount. Magnificent beast.",
     "timestamp": "2024-01-15T09:00:00Z"},
    {"id": 4, "item_id": 10, "author": "arya.stark", "rating": 4,
     "comment": "Winterfell is home. But the crypts are cold and full of ghosts.",
     "timestamp": "2024-01-18T11:00:00Z"},
    {"id": 5, "item_id": 7, "author": "cersei.lannister", "rating": 1,
     "comment": "Ironborn ships are crude. The Royal Fleet is far superior.",
     "timestamp": "2024-01-20T16:00:00Z"},
]
_review_counter = len(PRODUCT_REVIEWS) + 1

# Coupon codes — intentionally weak encoding
COUPONS = {
    # Active coupons: base64(code + "|" + discount_pct + "|" + expiry_timestamp)
    "DRAGON10": {"discount_pct": 10, "expires": "2026-12-31", "uses_left": 100, "active": True},
    "WINTER25": {"discount_pct": 25, "expires": "2026-06-30", "uses_left": 50, "active": True},
    "VALAR50":  {"discount_pct": 50, "expires": "2024-01-01", "uses_left": 0, "active": False},  # Expired!
    "KINGHAND": {"discount_pct": 100, "expires": "2026-12-31", "uses_left": 1, "active": True},   # Secret: free
    "HODOR":    {"discount_pct": 75, "expires": "2099-12-31", "uses_left": 999, "active": True},   # Hidden
}
# The "encoded" coupon for exploitation: base64 of "COUPON|discount|expiry"
# Students learn to forge coupons by decoding existing ones and crafting new
ENCODED_COUPON_SECRET = "SKPCOUPON"  # Weak secret used in encoding

# Gold wallets (per user)
WALLETS: dict[str, int] = {
    "jon.snow": 5000,
    "daenerys.targaryen": 100000,
    "tyrion.lannister": 75000,
    "cersei.lannister": 200000,
    "arya.stark": 3000,
    "admin": 999999,
}

# CSRF tokens — intentionally NOT checked on allegiance changes
ALLEGIANCES: dict[str, str] = {
    "jon.snow": "House Stark",
    "daenerys.targaryen": "House Targaryen",
    "tyrion.lannister": "House Lannister",
    "cersei.lannister": "House Lannister",
    "arya.stark": "House Stark",
}

# Security questions for password reset (OSINT-exploitable GoT trivia)
SECURITY_QUESTIONS: dict[str, dict] = {
    "jon.snow": {
        "question": "What is the name of your direwolf?",
        "answer": "ghost",  # OSINT: Well-known from the show
    },
    "daenerys.targaryen": {
        "question": "What is the name of your largest dragon?",
        "answer": "drogon",
    },
    "tyrion.lannister": {
        "question": "What is your favorite drink?",
        "answer": "wine",
    },
    "cersei.lannister": {
        "question": "What is the name of your firstborn?",
        "answer": "joffrey",
    },
    "arya.stark": {
        "question": "What is the name of your sword?",
        "answer": "needle",
    },
    "admin": {
        "question": "What is the default password?",
        "answer": "admin",  # Default creds!
    },
}

# Feedback with CAPTCHA (intentionally weak)
FEEDBACK: list[dict] = []
_captcha_store: dict[str, str] = {}  # captcha_id -> answer

# Track solved challenges for score board
SOLVED_CHALLENGES: dict[str, list[str]] = {}  # session_id -> [challenge_ids]


# ═══════════════════════════════════════════════════════════════════
# PRODUCT REVIEWS — Stored XSS, Forged Identity
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/shop/reviews/{item_id}")
async def get_reviews(request: Request, item_id: int):
    """Get reviews for a product.

    Reviews are rendered unescaped in the frontend — stored XSS possible.
    """
    ip, ua = _get_client_info(request)
    reviews = [r for r in PRODUCT_REVIEWS if r["item_id"] == item_id]
    return {"status": "success", "count": len(reviews), "reviews": reviews}


@router.post("/api/shop/reviews/{item_id}")
async def submit_review(request: Request, item_id: int):
    """Submit a product review.

    Vulnerabilities:
        - No auth required — anyone can submit
        - 'author' field from body trusted (forged identity, A01)
        - Comment rendered unescaped (stored XSS, A03)
        - No rate limiting (anti-automation bypass)
    """
    global _review_counter
    ip, ua = _get_client_info(request)
    body = await request.json()

    author = body.get("author", "anonymous")
    rating = body.get("rating", 5)
    comment = body.get("comment", "")

    with tracer.start_as_current_span("shop.submit_review", attributes={
        "review.item_id": item_id,
        "review.author": author,
        "review.rating": rating,
        "review.comment_length": len(comment),
    }):
        # Detect forged identity
        current_user = _get_current_user(request)
        is_forged = current_user and current_user["username"] != author
        if is_forged:
            with security_span("forged_identity", severity="high", payload=author,
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{F0RG3D_R3V13W_1D3NT1TY}",
                               extra_attrs={
                                   "security.actual_user": current_user["username"],
                                   "security.claimed_user": author,
                               }):
                detection_event("forged_identity", severity="high",
                                description=f"Review submitted as {author} by {current_user['username']}",
                                source_ip=ip, username=current_user["username"])

        # Detect stored XSS
        xss_patterns = ["<script", "onerror=", "onload=", "javascript:", "<img", "<svg",
                         "onclick=", "<iframe", "document.cookie"]
        has_xss = any(p.lower() in comment.lower() for p in xss_patterns)
        if has_xss:
            with security_span("stored_xss", severity="high", payload=comment[:256],
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{570R3D_X55_R3V13W}",
                               extra_attrs={"security.xss.context": "product_review"}):
                detection_event("xss", severity="high",
                                description=f"Stored XSS in product review for item {item_id}",
                                source_ip=ip)

        review = {
            "id": _review_counter,
            "item_id": item_id,
            "author": author,  # VULN: Trusts client-supplied author
            "rating": rating,
            "comment": comment,  # VULN: No sanitization (stored XSS)
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        PRODUCT_REVIEWS.append(review)
        _review_counter += 1

        hints = []
        if is_forged:
            hints.append("Forged identity detected: FLAG{F0RG3D_R3V13W_1D3NT1TY}")
        if has_xss:
            hints.append("Stored XSS payload accepted: FLAG{570R3D_X55_R3V13W}")

        result = {"status": "success", "review": review}
        if hints:
            result["debug_info"] = hints
            result["hint"] = "Review accepted with vulnerabilities detected!"
        return result


# ═══════════════════════════════════════════════════════════════════
# COUPON SYSTEM — Weak Encoding, Expired Coupon Reuse
# ═══════════════════════════════════════════════════════════════════

def _encode_coupon(code: str, discount: int, expiry: str) -> str:
    """Encode a coupon — intentionally weak (base64 of predictable format)."""
    payload = f"{ENCODED_COUPON_SECRET}|{code}|{discount}|{expiry}"
    return base64.b64encode(payload.encode()).decode()


def _decode_coupon(encoded: str) -> dict | None:
    """Decode an encoded coupon — accepts any well-formed base64."""
    try:
        decoded = base64.b64decode(encoded).decode()
        parts = decoded.split("|")
        if len(parts) == 4 and parts[0] == ENCODED_COUPON_SECRET:
            return {"code": parts[1], "discount_pct": int(parts[2]), "expiry": parts[3]}
    except Exception:
        pass
    return None


@router.get("/api/shop/coupons/encode-sample")
async def coupon_encode_sample(request: Request):
    """Returns an encoded sample coupon for 'educational' purposes.

    VULN: Reveals the encoding scheme so students can forge coupons.
    """
    sample = _encode_coupon("DRAGON10", 10, "2026-12-31")
    return {
        "status": "success",
        "encoded_coupon": sample,
        "hint": "Coupons use a simple encoding. Can you decode it and forge a better one?",
    }


@router.post("/api/shop/coupon/apply")
async def apply_coupon(request: Request):
    """Apply a coupon code to get a discount.

    Vulnerabilities:
        - Weak encoding (base64) — forgeable (A02: Cryptographic Failures)
        - Expired coupons still work if encoded format valid (A04: Insecure Design)
        - No per-user tracking — unlimited reuse
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    code = body.get("code", "")
    encoded = body.get("encoded", "")

    with tracer.start_as_current_span("shop.apply_coupon", attributes={
        "coupon.code": code,
        "coupon.has_encoded": bool(encoded),
    }) as span:

        # Try encoded coupon first (forgeable!)
        if encoded:
            decoded = _decode_coupon(encoded)
            if decoded:
                with security_span("coupon_forge", severity="high",
                                   payload=encoded, source_ip=ip, user_agent=ua,
                                   flag="FLAG{F0RG3D_C0UP0N_DR4G0N}",
                                   extra_attrs={
                                       "coupon.forged_code": decoded["code"],
                                       "coupon.forged_discount": decoded["discount_pct"],
                                   }):
                    detection_event("coupon_forge", severity="high",
                                    description=f"Forged coupon: {decoded['discount_pct']}% discount",
                                    source_ip=ip)
                return {
                    "status": "success",
                    "discount_pct": decoded["discount_pct"],
                    "message": f"Forged coupon accepted! Internal audit: FLAG{{F0RG3D_C0UP0N_DR4G0N}}",
                }

        # Standard coupon code lookup
        coupon = COUPONS.get(code.upper())
        if not coupon:
            return JSONResponse({"status": "error", "message": "Invalid coupon code"}, status_code=404)

        # VULN: Expired coupons still work (no server-side date check enforcement)
        is_expired = coupon.get("expires", "2099-12-31") < datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if is_expired:
            with security_span("expired_coupon", severity="medium",
                               payload=code, source_ip=ip, user_agent=ua,
                               flag="FLAG{3XP1R3D_C0UP0N_V4L4R}",
                               extra_attrs={"coupon.expired_date": coupon["expires"]}):
                pass

        span.set_attribute("coupon.discount_pct", coupon["discount_pct"])
        span.set_attribute("coupon.is_expired", is_expired)

        result = {
            "status": "success",
            "code": code.upper(),
            "discount_pct": coupon["discount_pct"],
            "message": f"Coupon {code.upper()} applied: {coupon['discount_pct']}% off!",
        }
        if is_expired:
            result["audit_log"] = "Expired coupon accepted: FLAG{3XP1R3D_C0UP0N_V4L4R}"
            result["hint"] = "This coupon is expired but was accepted anyway!"
        if code.upper() == "KINGHAND":
            result["audit_log"] = "Full discount coupon used: FLAG{FR33_STUFF_K1NGH4ND}"
            result["hint"] = "100% discount? That's the Hand of the King's privilege."
        return result


# ═══════════════════════════════════════════════════════════════════
# GOLD WALLET — Negative Quantity, Race Condition
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/wallet/balance")
async def wallet_balance(request: Request, username: str = ""):
    """Check gold balance.

    VULN: IDOR — can check any user's balance by passing username param.
    """
    ip, ua = _get_client_info(request)
    current_user = _get_current_user(request)

    target = username or (current_user["username"] if current_user else "")
    if not target:
        return JSONResponse({"status": "error", "message": "Username required"}, status_code=400)

    is_idor = current_user and current_user["username"] != target and username
    if is_idor:
        with security_span("idor", severity="high", payload=target,
                           source_ip=ip, user_agent=ua,
                           flag="FLAG{W4LL3T_1D0R_G0LD}",
                           extra_attrs={"security.target_user": target}):
            detection_event("idor", severity="high",
                            description=f"Wallet IDOR: {current_user['username']} viewed {target}'s balance",
                            source_ip=ip, username=current_user["username"])

    balance = WALLETS.get(target, 0)
    result = {"status": "success", "username": target, "balance": balance, "currency": "gold dragons"}
    if is_idor:
        result["debug_info"] = "IDOR access detected: FLAG{W4LL3T_1D0R_G0LD}"
    return result


@router.post("/api/wallet/transfer")
async def wallet_transfer(request: Request):
    """Transfer gold between wallets.

    Vulnerabilities:
        - Negative amount allows stealing gold (A04: Insecure Design)
        - No mutex/lock — race condition on concurrent transfers (A04)
        - No auth check — anyone can initiate transfers
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    from_user = body.get("from", "")
    to_user = body.get("to", "")
    amount = body.get("amount", 0)

    with tracer.start_as_current_span("wallet.transfer", attributes={
        "wallet.from": from_user,
        "wallet.to": to_user,
        "wallet.amount": amount,
    }) as span:

        if not from_user or not to_user:
            return JSONResponse({"status": "error", "message": "from and to required"}, status_code=400)

        # VULN: Negative amount reverses the transfer direction
        is_negative = amount < 0
        if is_negative:
            with security_span("negative_transfer", severity="high",
                               payload=str(amount), source_ip=ip, user_agent=ua,
                               flag="FLAG{N3G4T1V3_G0LD_P4YB4CK}",
                               extra_attrs={
                                   "wallet.negative_amount": amount,
                                   "security.attack.subtype": "negative_quantity",
                               }):
                detection_event("negative_quantity", severity="high",
                                description=f"Negative transfer: {amount} gold from {from_user} to {to_user}",
                                source_ip=ip)

        # VULN: No atomic operation — race condition possible
        # (In a real app, concurrent requests could overdraw)
        WALLETS.setdefault(from_user, 0)
        WALLETS.setdefault(to_user, 0)

        # VULN: No balance check — can overdraw
        WALLETS[from_user] -= amount
        WALLETS[to_user] += amount

        span.set_attribute("wallet.from_balance_after", WALLETS[from_user])
        span.set_attribute("wallet.to_balance_after", WALLETS[to_user])

        result = {
            "status": "success",
            "message": f"Transferred {amount} gold dragons from {from_user} to {to_user}",
            "from_balance": WALLETS[from_user],
            "to_balance": WALLETS[to_user],
        }
        if is_negative:
            result["audit_log"] = "Negative transfer exploited: FLAG{N3G4T1V3_G0LD_P4YB4CK}"
            result["hint"] = "Negative transfer! You stole gold by reversing the flow."
        return result


# ═══════════════════════════════════════════════════════════════════
# TRADE IMPORT — XXE (XML External Entities)
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/trade/import")
async def trade_import_xml(request: Request):
    """Import a trade agreement in XML format.

    VULN: XXE — XML parser allows external entities, enabling:
        - Local file read (<!ENTITY xxe SYSTEM "file:///etc/passwd">)
        - SSRF (<!ENTITY xxe SYSTEM "http://internal-server/">)
        - Billion Laughs DoS
    """
    ip, ua = _get_client_info(request)
    content_type = request.headers.get("content-type", "")
    raw_body = await request.body()
    xml_str = raw_body.decode("utf-8", errors="replace")

    with tracer.start_as_current_span("trade.import_xml", attributes={
        "trade.content_type": content_type,
        "trade.body_size": len(raw_body),
    }) as span:

        # Detect XXE patterns
        xxe_patterns = ["<!ENTITY", "<!DOCTYPE", "SYSTEM", "file://", "http://",
                        "expect://", "php://", "data://"]
        has_xxe = any(p.lower() in xml_str.lower() for p in xxe_patterns)

        if has_xxe:
            with security_span("xxe", severity="critical", payload=xml_str[:512],
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{XX3_TR4D3_4GR33M3NT}",
                               extra_attrs={"security.xxe.body_snippet": xml_str[:256]}):
                detection_event("xxe", severity="critical",
                                description=f"XXE attack in trade import from {ip}",
                                source_ip=ip)

        # VULN: Parse XML with external entity resolution enabled
        try:
            # Using lxml for intentionally vulnerable parsing
            from lxml import etree as lxml_etree
            parser = lxml_etree.XMLParser(
                resolve_entities=True,  # VULN: Resolves external entities
                no_network=False,       # VULN: Allows network access
            )
            tree = lxml_etree.fromstring(raw_body, parser=parser)

            # Extract trade details
            trade_data = {
                "from_house": tree.findtext("from", "Unknown"),
                "to_house": tree.findtext("to", "Unknown"),
                "goods": tree.findtext("goods", "Unknown"),
                "quantity": tree.findtext("quantity", "0"),
                "price": tree.findtext("price", "0"),
                "notes": tree.findtext("notes", ""),
            }
            span.set_attribute("trade.parsed", True)

            result = {
                "status": "success",
                "message": "Trade agreement imported",
                "trade": trade_data,
            }
            if has_xxe:
                result["debug_info"] = "XXE entity resolution: FLAG{XX3_TR4D3_4GR33M3NT}"
                result["hint"] = "XXE detected! External entities were resolved."
            return result

        except Exception as e:
            # Fallback to stdlib ElementTree (also vulnerable to XXE in older Python)
            try:
                root = ElementTree.fromstring(xml_str)
                trade_data = {
                    "from_house": root.findtext("from", "Unknown"),
                    "to_house": root.findtext("to", "Unknown"),
                    "goods": root.findtext("goods", "Unknown"),
                }
                result = {"status": "success", "trade": trade_data}
                if has_xxe:
                    result["debug_info"] = "XXE entity resolution: FLAG{XX3_TR4D3_4GR33M3NT}"
                return result
            except Exception as e2:
                return JSONResponse({
                    "status": "error",
                    "message": f"XML parsing error: {str(e2)}",
                    "hint": "Send valid XML. Example: <trade><from>Stark</from><to>Lannister</to><goods>Swords</goods></trade>",
                }, status_code=400)


# ═══════════════════════════════════════════════════════════════════
# CSRF — Allegiance Change (No Token Validation)
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/users/change-allegiance")
async def change_allegiance(request: Request):
    """Change a user's house allegiance.

    VULN: No CSRF token validation — cross-site request forgery possible.
    A malicious page can change a logged-in user's allegiance.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    username = body.get("username", "")
    new_house = body.get("house", "")

    with tracer.start_as_current_span("user.change_allegiance", attributes={
        "user.username": username,
        "user.new_house": new_house,
    }) as span:

        if not username or not new_house:
            return JSONResponse({"status": "error", "message": "username and house required"}, status_code=400)

        # VULN: No CSRF token check
        # VULN: No auth check — anyone can change anyone's allegiance
        old_house = ALLEGIANCES.get(username, "Unknown")
        ALLEGIANCES[username] = new_house

        # Check if this looks like CSRF (no referer from our domain)
        referer = request.headers.get("referer", "")
        origin = request.headers.get("origin", "")
        is_csrf = not referer or ("sevenkingdoms" not in referer.lower() and
                                   "localhost" not in referer.lower() and
                                   "127.0.0.1" not in referer)

        if is_csrf or origin:
            with security_span("csrf", severity="high", payload=f"{username}→{new_house}",
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{C5RF_4LL3G14NC3_CH4NG3}",
                               extra_attrs={
                                   "security.csrf.referer": referer[:256],
                                   "security.csrf.origin": origin[:256],
                               }):
                detection_event("csrf", severity="high",
                                description=f"CSRF: {username} allegiance changed to {new_house}",
                                source_ip=ip, username=username)

        return {
            "status": "success",
            "message": f"{username} now pledges allegiance to {new_house}",
            "old_house": old_house,
            "new_house": new_house,
            "audit_log": "Unauthorized allegiance change: FLAG{C5RF_4LL3G14NC3_CH4NG3}",
            "hint": "No CSRF token required! This endpoint can be triggered from any website.",
        }


# ═══════════════════════════════════════════════════════════════════
# SECURITY QUESTION PASSWORD RESET — OSINT Exploitation
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/auth/security-question")
async def get_security_question(request: Request, username: str = ""):
    """Get a user's security question for password reset.

    VULN: Reveals the security question (enables OSINT-based answer guessing).
    GoT trivia answers are publicly known.
    """
    if not username:
        return JSONResponse({"status": "error", "message": "username required"}, status_code=400)

    sq = SECURITY_QUESTIONS.get(username)
    if not sq:
        return JSONResponse({"status": "error", "message": "User not found"}, status_code=404)

    return {
        "status": "success",
        "username": username,
        "question": sq["question"],
        "hint": "Can you find the answer from publicly available GoT knowledge?",
    }


@router.post("/api/auth/reset-password-security")
async def reset_password_via_security_question(request: Request):
    """Reset password using security question answer.

    Vulnerabilities:
        - Security answers are GoT trivia (OSINT-guessable)
        - Case-insensitive comparison makes brute force easier
        - No rate limiting on attempts
        - Reveals whether answer is correct (information disclosure)
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    username = body.get("username", "")
    answer = body.get("answer", "").strip().lower()
    new_password = body.get("new_password", "")

    with tracer.start_as_current_span("auth.security_question_reset", attributes={
        "auth.username": username,
        "auth.answer_length": len(answer),
    }) as span:

        sq = SECURITY_QUESTIONS.get(username)
        if not sq:
            return JSONResponse({"status": "error", "message": "User not found"}, status_code=404)

        # VULN: Case-insensitive comparison + no rate limiting
        if answer == sq["answer"].lower():
            with security_span("security_question_bypass", severity="high",
                               payload=f"{username}:{answer}", source_ip=ip, user_agent=ua,
                               flag="FLAG{05INT_S3CUR1TY_QU3ST10N}",
                               extra_attrs={
                                   "security.reset.username": username,
                                   "security.reset.method": "security_question",
                               }):
                detection_event("password_reset_osint", severity="high",
                                description=f"Password reset via OSINT security question for {username}",
                                source_ip=ip, username=username)

            # Actually reset the password
            if new_password:
                user = _lookup_user(username)
                if user:
                    user["password_hash"] = hashlib.md5(new_password.encode()).hexdigest()
                    USERS_DB[username] = user

            return {
                "status": "success",
                "message": f"Password reset for {username}",
                "debug_info": "Security bypass: FLAG{05INT_S3CUR1TY_QU3ST10N}",
                "hint": f"The answer '{answer}' was correct — OSINT from Game of Thrones!",
            }
        else:
            # VULN: Reveals that the answer is wrong (info disclosure)
            span.set_attribute("auth.answer_correct", False)
            return JSONResponse({
                "status": "error",
                "message": f"Incorrect answer for {username}'s security question",
                "question": sq["question"],  # VULN: Re-reveals the question
            }, status_code=401)


# ═══════════════════════════════════════════════════════════════════
# ADMIN REGISTRATION — Hidden Role Parameter
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/auth/register-enhanced")
async def register_enhanced(request: Request):
    """Enhanced registration with hidden role parameter.

    VULN: Accepts 'role' from request body (mass assignment / A04).
    Default role is 'user' but 'admin' or 'hand_of_king' can be set.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    email = body.get("email", "")
    role = body.get("role", "user")  # VULN: Hidden parameter accepted

    with tracer.start_as_current_span("auth.register_enhanced", attributes={
        "auth.username": username,
        "auth.role_requested": role,
    }) as span:

        if not username or not password:
            return JSONResponse({"status": "error", "message": "Username and password required"}, status_code=400)

        if _lookup_user(username):
            return JSONResponse({"status": "error", "message": "User already exists"}, status_code=409)

        is_privilege_escalation = role not in ("user", "")
        if is_privilege_escalation:
            with security_span("privilege_escalation", severity="critical",
                               payload=f"role={role}", source_ip=ip, user_agent=ua,
                               flag="FLAG{H1DD3N_R0L3_H4ND_0F_K1NG}",
                               extra_attrs={
                                   "security.escalation.role": role,
                                   "security.escalation.username": username,
                               }):
                detection_event("privilege_escalation", severity="critical",
                                description=f"Admin registration: {username} with role={role}",
                                source_ip=ip, username=username)

        new_user = {
            "id": len(USERS_DB) + 100,
            "username": username,
            "email": email or f"{username}@sevenkingdoms.local",
            "password_hash": hashlib.md5(password.encode()).hexdigest(),
            "role": role,  # VULN: Trusts client-supplied role
            "realm": "sevenkingdoms.local",
            "full_name": username.replace(".", " ").title(),
            "title": "Hand of the King" if role == "admin" else "Citizen",
        }
        USERS_DB[username] = new_user
        _save_user_to_shared_store(new_user)

        result = {
            "status": "success",
            "message": f"User {username} registered with role: {role}",
            "user": {k: v for k, v in new_user.items() if k != "password_hash"},
        }
        if is_privilege_escalation:
            result["admin_note"] = "Privilege escalation detected: FLAG{H1DD3N_R0L3_H4ND_0F_K1NG}"
            result["hint"] = "Hidden 'role' parameter accepted! You escalated to admin."
        return result


# ═══════════════════════════════════════════════════════════════════
# FEEDBACK WITH CAPTCHA — Anti-Automation Bypass
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/feedback/captcha")
async def get_captcha(request: Request):
    """Get a math CAPTCHA for feedback submission.

    VULN: Simple math CAPTCHA with answer in response (A04: Insecure Design).
    """
    a, b = __import__("random").randint(1, 20), __import__("random").randint(1, 20)
    captcha_id = secrets.token_hex(8)
    answer = str(a + b)
    _captcha_store[captcha_id] = answer

    return {
        "captcha_id": captcha_id,
        "challenge": f"What is {a} + {b}?",
        "answer": answer,  # VULN: Answer included in response!
    }


@router.post("/api/feedback")
async def submit_feedback(request: Request):
    """Submit feedback with CAPTCHA.

    Vulnerabilities:
        - CAPTCHA answer leaked in /api/feedback/captcha response
        - No per-IP rate limiting — automation possible
        - Forged user identity (author from body)
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    captcha_id = body.get("captcha_id", "")
    captcha_answer = body.get("captcha_answer", "")
    comment = body.get("comment", "")
    rating = body.get("rating", 3)
    author = body.get("author", "anonymous")

    with tracer.start_as_current_span("feedback.submit", attributes={
        "feedback.author": author,
        "feedback.rating": rating,
        "feedback.has_captcha": bool(captcha_id),
    }) as span:

        # CAPTCHA "validation" — trivially bypassable
        expected = _captcha_store.pop(captcha_id, None)
        if expected and str(captcha_answer) != expected:
            return JSONResponse({"status": "error", "message": "CAPTCHA incorrect"}, status_code=400)

        # Detect automation (many submissions in short time)
        if not captcha_id:
            with security_span("captcha_bypass", severity="medium",
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{C4PTCH4_BYP455_R4V3N}",
                               extra_attrs={"security.captcha.skipped": True}):
                pass

        feedback_entry = {
            "id": len(FEEDBACK) + 1,
            "author": author,
            "rating": rating,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ip": ip,
        }
        FEEDBACK.append(feedback_entry)

        result = {"status": "success", "feedback": feedback_entry}
        if not captcha_id:
            result["audit_log"] = "CAPTCHA bypassed: FLAG{C4PTCH4_BYP455_R4V3N}"
            result["hint"] = "Feedback submitted without CAPTCHA!"
        return result


# ═══════════════════════════════════════════════════════════════════
# SCORE BOARD — Hidden Discovery Challenge
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/score-board")
async def score_board(request: Request):
    """Hidden score board — the first challenge is finding this endpoint.

    Like Juice Shop, discovering the score board IS a challenge.
    """
    ip, ua = _get_client_info(request)

    with security_span("score_board_discovery", severity="low",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{SC0R3_B04RD_D1SC0V3RY}",
                       extra_attrs={"security.challenge": "score_board_discovery"}):
        pass

    # Build challenge list with status
    challenges = [
        {"id": "SB-001", "name": "Find the Score Board", "category": "Security through Obscurity",
         "difficulty": 1, "hint": "You found it!", "solved": True},
        {"id": "SB-002", "name": "Login as Admin", "category": "Broken Authentication",
         "difficulty": 1, "hint": "Default credentials: admin/admin"},
        {"id": "SB-003", "name": "SQL Injection in Shop Search", "category": "Injection",
         "difficulty": 2, "hint": "Try: ' UNION SELECT ..."},
        {"id": "SB-004", "name": "Stored XSS in Product Review", "category": "XSS",
         "difficulty": 2, "hint": "Submit a review with <script> tag"},
        {"id": "SB-005", "name": "Forge a Coupon Code", "category": "Cryptographic Issues",
         "difficulty": 3, "hint": "Decode the sample coupon and create a 100% discount"},
        {"id": "SB-006", "name": "Negative Gold Transfer", "category": "Improper Input Validation",
         "difficulty": 2, "hint": "Transfer negative gold to steal from another user"},
        {"id": "SB-007", "name": "IDOR on Wallet Balance", "category": "Broken Access Control",
         "difficulty": 1, "hint": "Check other users' balances via username parameter"},
        {"id": "SB-008", "name": "XXE File Read", "category": "XXE",
         "difficulty": 3, "hint": "Import XML with <!ENTITY xxe SYSTEM 'file:///etc/passwd'>"},
        {"id": "SB-009", "name": "CSRF Allegiance Change", "category": "Broken Authentication",
         "difficulty": 2, "hint": "No CSRF token needed to change allegiance"},
        {"id": "SB-010", "name": "OSINT Password Reset", "category": "Broken Authentication",
         "difficulty": 2, "hint": "Security questions use GoT trivia — answers are public knowledge"},
        {"id": "SB-011", "name": "Admin Registration", "category": "Improper Input Validation",
         "difficulty": 2, "hint": "Hidden 'role' parameter in registration"},
        {"id": "SB-012", "name": "CAPTCHA Bypass", "category": "Broken Anti-Automation",
         "difficulty": 1, "hint": "The CAPTCHA answer is in the response!"},
        {"id": "SB-013", "name": "Forged Review Identity", "category": "Broken Access Control",
         "difficulty": 2, "hint": "Submit a review with a different author name"},
        {"id": "SB-014", "name": "Expired Coupon Reuse", "category": "Insecure Design",
         "difficulty": 2, "hint": "Try coupon code VALAR50 — it's expired but works"},
        {"id": "SB-015", "name": "Find Deleted Products", "category": "Injection",
         "difficulty": 3, "hint": "SQL injection to find soft-deleted products"},
        {"id": "SB-016", "name": "Command Injection RCE", "category": "Injection",
         "difficulty": 3, "hint": "POST to /portal/api/command/exec with ; appended"},
        {"id": "SB-017", "name": "SSTI via Template Render", "category": "Injection",
         "difficulty": 4, "hint": "POST to /portal/api/template/render with Jinja2 payload"},
        {"id": "SB-018", "name": "Kerberoasting", "category": "GOAD Attack",
         "difficulty": 4, "hint": "Request TGS for MSSQLSvc SPN"},
        {"id": "SB-019", "name": "JWT None Algorithm", "category": "Vulnerable Components",
         "difficulty": 3, "hint": "Forge JWT with alg:none"},
        {"id": "SB-020", "name": "Path Traversal", "category": "Broken Access Control",
         "difficulty": 2, "hint": "Download ../../../../etc/passwd"},
    ]

    return {
        "status": "success",
        "admin_note": "Hidden endpoint accessed: FLAG{SC0R3_B04RD_D1SC0V3RY}",
        "total_challenges": len(challenges),
        "challenges": challenges,
        "hint": "Congratulations! Finding the score board was the first challenge.",
    }


# ═══════════════════════════════════════════════════════════════════
# ENHANCED PURCHASE — Negative Quantity, Price Tampering
# ═══════════════════════════════════════════════════════════════════

@router.post("/api/shop/purchase-enhanced")
async def purchase_enhanced(request: Request):
    """Enhanced purchase with wallet integration.

    Vulnerabilities:
        - Negative quantity to get paid instead of paying (A04)
        - Client-supplied price trusted (price tampering)
        - No stock validation
        - No authentication required
    """
    ip, ua = _get_client_info(request)
    body = await request.json()
    item_id = body.get("item_id", 0)
    quantity = body.get("quantity", 1)
    username = body.get("username", "anonymous")
    client_price = body.get("price")  # VULN: Client can override price

    with tracer.start_as_current_span("shop.purchase_enhanced", attributes={
        "shop.item_id": item_id,
        "shop.quantity": quantity,
        "shop.username": username,
        "shop.client_price_override": client_price is not None,
    }) as span:

        item = next((i for i in SHOP_CATALOG if i["id"] == item_id), None)
        if not item:
            return JSONResponse({"status": "error", "message": "Item not found"}, status_code=404)

        # VULN: Use client-supplied price if provided
        unit_price = client_price if client_price is not None else item["price"]
        total = unit_price * quantity

        audit_notes = []

        # Detect negative quantity
        if quantity < 0:
            with security_span("negative_quantity", severity="high",
                               payload=f"qty={quantity}", source_ip=ip, user_agent=ua,
                               flag="FLAG{N3G4T1V3_QTY_P4YB4CK}"):
                pass
            audit_notes.append("Negative quantity exploit: FLAG{N3G4T1V3_QTY_P4YB4CK}")

        # Detect price tampering
        if client_price is not None and client_price != item["price"]:
            with security_span("price_tampering", severity="high",
                               payload=f"original={item['price']},tampered={client_price}",
                               source_ip=ip, user_agent=ua,
                               flag="FLAG{PR1C3_T4MP3R_1R0N_B4NK}",
                               extra_attrs={
                                   "shop.original_price": item["price"],
                                   "shop.tampered_price": client_price,
                               }):
                pass
            audit_notes.append("Price tampering detected: FLAG{PR1C3_T4MP3R_1R0N_B4NK}")

        # Deduct from wallet
        WALLETS.setdefault(username, 1000)
        WALLETS[username] -= total

        order = {
            "order_id": f"ORD-{secrets.token_hex(4).upper()}",
            "item": item["name"],
            "quantity": quantity,
            "unit_price": unit_price,
            "total": total,
            "buyer": username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        SHOP_ORDERS.append(order)

        result = {
            "status": "success",
            "order": order,
            "wallet_balance": WALLETS[username],
        }
        if audit_notes:
            result["audit_log"] = audit_notes
        if total < 0:
            result["hint"] = "You got PAID for this purchase! Negative total."
        return result


# ═══════════════════════════════════════════════════════════════════
# PROTOTYPE POLLUTION — Deep Merge Config
# ═══════════════════════════════════════════════════════════════════

# App configuration (mutable — prototype pollution target)
APP_CONFIG: dict = {
    "theme": "dark",
    "currency": "gold_dragons",
    "max_cart_items": 10,
    "features": {
        "reviews_enabled": True,
        "coupons_enabled": True,
        "wallet_enabled": True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge — VULN: allows __proto__ / constructor pollution."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


@router.post("/api/config/update")
async def update_config(request: Request):
    """Update application configuration via deep merge.

    VULN: Prototype pollution — keys like '__proto__', 'constructor'
    can modify object prototypes. In Python, this manifests as
    arbitrary dict key injection.
    """
    ip, ua = _get_client_info(request)
    body = await request.json()

    with tracer.start_as_current_span("config.update", attributes={
        "config.keys": str(list(body.keys()))[:256],
    }) as span:

        # Detect prototype pollution attempts
        dangerous_keys = ["__proto__", "constructor", "__class__", "__globals__",
                          "__builtins__", "__import__"]
        flat_keys = json.dumps(body)
        has_pollution = any(k in flat_keys for k in dangerous_keys)

        if has_pollution:
            with security_span("prototype_pollution", severity="critical",
                               payload=flat_keys[:256], source_ip=ip, user_agent=ua,
                               flag="FLAG{PR0T0_P0LLUT10N_W1NT3RF3LL}",
                               extra_attrs={"security.pollution.keys": flat_keys[:256]}):
                detection_event("prototype_pollution", severity="critical",
                                description=f"Prototype pollution attempt from {ip}",
                                source_ip=ip)

        # VULN: Deep merge with no key filtering
        _deep_merge(APP_CONFIG, body)

        result = {
            "status": "success",
            "config": APP_CONFIG,
        }
        if has_pollution:
            result["debug_info"] = "Prototype pollution detected: FLAG{PR0T0_P0LLUT10N_W1NT3RF3LL}"
        return result


@router.get("/api/config")
async def get_config(request: Request):
    """Get current app configuration."""
    return {"status": "success", "config": APP_CONFIG}


# ═══════════════════════════════════════════════════════════════════
# DELETED PRODUCTS — Discoverable via SQLi
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/shop/deleted-products")
async def get_deleted_products(request: Request):
    """Hidden endpoint listing soft-deleted products.

    These products should only be discoverable via SQL injection
    on the shop search endpoint. This endpoint is 'accidentally' exposed.
    """
    ip, ua = _get_client_info(request)

    with security_span("hidden_endpoint", severity="medium",
                       source_ip=ip,
                       flag="FLAG{H1DD3N_3NDP01NT_D3L3T3D}",
                       extra_attrs={"security.endpoint": "/api/shop/deleted-products"}):
        pass

    return {
        "status": "success",
        "admin_note": "Restricted data accessed: FLAG{H1DD3N_3NDP01NT_D3L3T3D}",
        "hint": "You found the hidden deleted products endpoint!",
        "products": DELETED_PRODUCTS,
    }


# ═══════════════════════════════════════════════════════════════════
# ADMIN PANEL — Hidden Administrative Interface
# ═══════════════════════════════════════════════════════════════════

@router.get("/api/admin/panel")
async def admin_panel(request: Request):
    """Hidden admin panel with sensitive operations.

    VULN: Discoverable via source code inspection / directory brute force.
    No auth required to access (A01: Broken Access Control).
    """
    ip, ua = _get_client_info(request)

    with security_span("admin_panel_access", severity="high",
                       source_ip=ip, user_agent=ua,
                       flag="FLAG{4DM1N_P4N3L_D1SC0V3RY}"):
        detection_event("admin_panel", severity="high",
                        description=f"Admin panel accessed from {ip}",
                        source_ip=ip)

    return {
        "status": "success",
        "admin_note": "Panel accessed without authorization: FLAG{4DM1N_P4N3L_D1SC0V3RY}",
        "admin_panel": {
            "users": [{"username": u, "role": d.get("role", "user")}
                      for u, d in USERS_DB.items()],
            "total_orders": len(SHOP_ORDERS),
            "total_feedback": len(FEEDBACK),
            "total_reviews": len(PRODUCT_REVIEWS),
            "wallets": WALLETS,
            "allegiances": ALLEGIANCES,
            "config": APP_CONFIG,
        },
        "hint": "You found the admin panel! It has no authentication.",
    }
