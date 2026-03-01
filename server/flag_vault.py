"""
Flag Vault — Central registry for all CTF flags in the Seven Kingdoms Portal.

Flags are no longer returned as top-level JSON keys in API responses.
Instead, they are embedded contextually in response data (e.g., in command
output, UNION query results, file contents, etc.).

This module provides:
  - FLAG_REGISTRY: Complete catalog of all flags with metadata
  - validate_flag(): Check if a submitted flag is correct
  - get_scoreboard(): Summary stats for the flag submission UI
"""

FLAG_REGISTRY = {
    # ── Injection ────────────────────────────────
    "sqli_treasury": {
        "flag": "FLAG{7R345URY_SQL1_BR34CH}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Treasury",
        "description": "SQL injection in treasury search endpoint",
    },
    "cmdi": {
        "flag": "FLAG{C0MM4ND_1NJ3CT10N_RCE}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "System Console",
        "description": "OS command injection via exec endpoint",
    },
    "ssti": {
        "flag": "FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "System Console",
        "description": "Server-side template injection",
    },
    "ldap_filter": {
        "flag": "FLAG{LD4P_F1LT3R_1NJ3CT10N}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "User Directory",
        "description": "LDAP filter injection in user lookup",
    },
    "ldap_login": {
        "flag": "FLAG{LD4P_1NJ3C710N_K1NG5L4ND1NG}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Authentication",
        "description": "LDAP injection via login endpoint",
    },
    "nosql_injection": {
        "flag": "FLAG{N0SQL_0P3R4T0R_1NJ3CT10N}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "System Console",
        "description": "NoSQL operator injection",
    },
    "log_injection": {
        "flag": "FLAG{L0G_1NJ3CT10N_F0RG3RY}",
        "difficulty": 2, "points": 200, "category": "injection",
        "module": "System Console",
        "description": "Log injection/forgery via crafted input",
    },
    "shop_sqli_search": {
        "flag": "FLAG{SH0P_SQL1_M4RK3T}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Marketplace",
        "description": "SQL injection in shop item search",
    },
    "shop_sqli_orders": {
        "flag": "FLAG{SH0P_0RD3R_SQL1}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Marketplace",
        "description": "SQL injection in order history lookup",
    },

    # ── SSRF ─────────────────────────────────────
    "ssrf_avatar": {
        "flag": "FLAG{55RF_1NT3RN4L_4CC355}",
        "difficulty": 3, "points": 300, "category": "ssrf",
        "module": "Network Tools",
        "description": "SSRF via avatar fetch to internal services",
    },
    "ssrf_mother": {
        "flag": "FLAG{M07H3R_0F_DR4G0N5_55RF}",
        "difficulty": 3, "points": 300, "category": "ssrf",
        "module": "Network Tools",
        "description": "SSRF to cloud metadata endpoint",
    },
    "webhook_ssrf": {
        "flag": "FLAG{W3BH00K_55RF_1NT3RN4L}",
        "difficulty": 3, "points": 300, "category": "ssrf",
        "module": "Network Tools",
        "description": "SSRF via webhook to internal network",
    },

    # ── Path Traversal / LFI ─────────────────────
    "path_traversal": {
        "flag": "FLAG{P4TH_TR4V3RS4L_LFI}",
        "difficulty": 2, "points": 200, "category": "path_traversal",
        "module": "File Manager",
        "description": "Local file inclusion via path traversal",
    },

    # ── XSS ──────────────────────────────────────
    "stored_xss": {
        "flag": "FLAG{570R3D_X55_R4V3N}",
        "difficulty": 2, "points": 200, "category": "xss",
        "module": "Ravens & Messages",
        "description": "Stored XSS via raven message",
    },

    # ── IDOR / Access Control ────────────────────
    "idor_profile": {
        "flag": "FLAG{1D0R_PR0F1L3_L34K}",
        "difficulty": 2, "points": 200, "category": "idor",
        "module": "User Directory",
        "description": "IDOR to access other user profiles",
    },
    "idor_treasury": {
        "flag": "FLAG{7R345URY_4CC355}",
        "difficulty": 2, "points": 200, "category": "idor",
        "module": "Treasury",
        "description": "IDOR to access classified treasury records",
    },
    "idor_messages": {
        "flag": "FLAG{R4V3N_1NT3RC3PT}",
        "difficulty": 2, "points": 200, "category": "idor",
        "module": "Ravens & Messages",
        "description": "IDOR to read other users' messages",
    },
    "shop_idor_secret": {
        "flag": "FLAG{SH0P_1D0R_S3CR3T}",
        "difficulty": 2, "points": 200, "category": "idor",
        "module": "Marketplace",
        "description": "IDOR to access secret shop item details",
    },

    # ── Authentication / Session ─────────────────
    "jwt_none": {
        "flag": "FLAG{JW7_N0N3_4LG0_BYPA55}",
        "difficulty": 4, "points": 400, "category": "auth",
        "module": "Administration",
        "description": "JWT algorithm none bypass for admin access",
    },
    "session_fixation": {
        "flag": "FLAG{S3SS10N_F1X4T10N_4TT4CK}",
        "difficulty": 3, "points": 300, "category": "auth",
        "module": "Authentication",
        "description": "Session fixation attack",
    },
    "mass_assignment": {
        "flag": "FLAG{M455_4551GNM3N7_PR1V35C}",
        "difficulty": 3, "points": 300, "category": "auth",
        "module": "Authentication",
        "description": "Mass assignment to escalate privileges",
    },
    "predictable_reset": {
        "flag": "FLAG{PR3D1CT4BL3_R3S3T}",
        "difficulty": 2, "points": 200, "category": "auth",
        "module": "Authentication",
        "description": "Predictable password reset token",
    },
    "credential_dump": {
        "flag": "FLAG{CR3D3NT14L_DUMP_MD5}",
        "difficulty": 2, "points": 200, "category": "auth",
        "module": "User Directory",
        "description": "Debug mode credential dump with MD5 hashes",
    },
    "default_creds": {
        "flag": "FLAG{D3F4ULT_CR3D5_4DM1N}",
        "difficulty": 1, "points": 100, "category": "auth",
        "module": "Authentication",
        "description": "Default admin credentials",
    },

    # ── Crypto / Debug ───────────────────────────
    "crypto_debug": {
        "flag": "FLAG{CRYPT0_F41LUR3_D3BUG}",
        "difficulty": 2, "points": 200, "category": "crypto",
        "module": "Administration",
        "description": "Crypto configuration leak via debug endpoint",
    },
    "env_leak": {
        "flag": "FLAG{3NV_L34K_D3BUG_M0D3}",
        "difficulty": 1, "points": 100, "category": "crypto",
        "module": "Administration",
        "description": "Environment variable leak via debug endpoint",
    },

    # ── Business Logic ───────────────────────────
    "negative_transfer": {
        "flag": "FLAG{N3G4T1V3_TR4NSF3R_L0G1C}",
        "difficulty": 3, "points": 300, "category": "logic",
        "module": "Treasury",
        "description": "Negative amount transfer exploit",
    },
    "open_redirect": {
        "flag": "FLAG{0P3N_R3D1R3CT}",
        "difficulty": 1, "points": 100, "category": "logic",
        "module": "External Links",
        "description": "Open redirect for phishing",
    },
    "crlf_injection": {
        "flag": "FLAG{CRLF_H34D3R_1NJ3CT10N}",
        "difficulty": 3, "points": 300, "category": "logic",
        "module": "External Links",
        "description": "CRLF header injection via redirect",
    },
    "open_redirect_phish": {
        "flag": "FLAG{0P3N_R3D1R3CT_PH1SH}",
        "difficulty": 1, "points": 100, "category": "logic",
        "module": "External Links",
        "description": "Open redirect usable for phishing",
    },

    # ── Deserialization ──────────────────────────
    "deserialization": {
        "flag": "FLAG{D3S3R14L1Z4T10N_RC3}",
        "difficulty": 5, "points": 500, "category": "deserialization",
        "module": "Data Import",
        "description": "Pickle deserialization RCE",
    },
    "proto_pollution": {
        "flag": "FLAG{PR0T0_P0LLUT10N}",
        "difficulty": 4, "points": 400, "category": "deserialization",
        "module": "Data Import",
        "description": "Prototype pollution via JSON import",
    },
    "proto_pollution_shop": {
        "flag": "FLAG{PR0T0_P0LLUT10N_W1NT3RF3LL}",
        "difficulty": 4, "points": 400, "category": "deserialization",
        "module": "Marketplace",
        "description": "Prototype pollution via config update endpoint",
    },

    # ── GOAD / Active Directory ──────────────────
    "kerberoast": {
        "flag": "FLAG{K3RB3R04ST_T1CK3T}",
        "difficulty": 4, "points": 400, "category": "goad",
        "module": "GOAD AD",
        "description": "Kerberoasting attack simulation",
    },
    "dcsync": {
        "flag": "FLAG{DC5YNC_R3PL1C4T10N}",
        "difficulty": 5, "points": 500, "category": "goad",
        "module": "GOAD AD",
        "description": "DCSync replication attack simulation",
    },

    # ── Shop / E-Commerce ────────────────────────
    "forged_coupon": {
        "flag": "FLAG{F0RG3D_C0UP0N_DR4G0N}",
        "difficulty": 3, "points": 300, "category": "shop",
        "module": "Marketplace",
        "description": "Forged coupon with manipulated signature",
    },
    "csrf_allegiance": {
        "flag": "FLAG{C5RF_4LL3G14NC3_CH4NG3}",
        "difficulty": 3, "points": 300, "category": "shop",
        "module": "Marketplace",
        "description": "CSRF to change user allegiance",
    },
    "osint_security_q": {
        "flag": "FLAG{05INT_S3CUR1TY_QU3ST10N}",
        "difficulty": 2, "points": 200, "category": "shop",
        "module": "Marketplace",
        "description": "OSINT-based security question bypass",
    },
    "scoreboard_discovery": {
        "flag": "FLAG{SC0R3_B04RD_D1SC0V3RY}",
        "difficulty": 1, "points": 100, "category": "shop",
        "module": "Marketplace",
        "description": "Hidden scoreboard endpoint discovery",
    },
    "deleted_products": {
        "flag": "FLAG{H1DD3N_3NDP01NT_D3L3T3D}",
        "difficulty": 2, "points": 200, "category": "shop",
        "module": "Marketplace",
        "description": "Access to deleted/hidden products",
    },
    "admin_panel_discovery": {
        "flag": "FLAG{4DM1N_P4N3L_D1SC0V3RY}",
        "difficulty": 2, "points": 200, "category": "shop",
        "module": "Marketplace",
        "description": "Admin panel endpoint discovery",
    },
    "shop_price_manipulation": {
        "flag": "FLAG{PR1C3_M4N1PUL4T10N_SH0P}",
        "difficulty": 3, "points": 300, "category": "shop",
        "module": "Marketplace",
        "description": "Client-side price manipulation",
    },
    "shop_purchase": {
        "flag": "FLAG{SH0P_PURCH4S3_C0MPL3T3}",
        "difficulty": 2, "points": 200, "category": "shop",
        "module": "Marketplace",
        "description": "Shop purchase completion flag",
    },
    "wallet_idor": {
        "flag": "FLAG{W4LL3T_1D0R_G0LD}",
        "difficulty": 2, "points": 200, "category": "shop",
        "module": "Marketplace",
        "description": "Wallet IDOR to view other users' gold",
    },
    "negative_gold": {
        "flag": "FLAG{N3G4T1V3_G0LD_P4YB4CK}",
        "difficulty": 3, "points": 300, "category": "shop",
        "module": "Marketplace",
        "description": "Negative gold transfer exploit",
    },
    "webshell_upload": {
        "flag": "FLAG{W3B_5H3LL_UPL04D3D}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "File Manager",
        "description": "Web shell upload via file endpoint",
    },
    "xss_review": {
        "flag": "FLAG{570R3D_X55_R3V13W}",
        "difficulty": 2, "points": 200, "category": "xss",
        "module": "Marketplace",
        "description": "Stored XSS via product review",
    },
    "price_tampering": {
        "flag": "FLAG{PR1C3_T4MP3R_1R0N_B4NK}",
        "difficulty": 3, "points": 300, "category": "shop",
        "module": "Marketplace",
        "description": "Client-side price tampering",
    },
    "hidden_admin_role": {
        "flag": "FLAG{H1DD3N_R0L3_H4ND_0F_K1NG}",
        "difficulty": 3, "points": 300, "category": "auth",
        "module": "Authentication",
        "description": "Hidden admin role assignment during registration",
    },
    "captcha_bypass": {
        "flag": "FLAG{C4PTCH4_BYP455_R4V3N}",
        "difficulty": 2, "points": 200, "category": "logic",
        "module": "Marketplace",
        "description": "CAPTCHA bypass on feedback form",
    },

    # ── XXE ──────────────────────────────────────
    "xxe_trade": {
        "flag": "FLAG{XX3_TR4D3_4GR33M3NT}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "Data Import",
        "description": "XXE via trade XML import",
    },

    # ── Infrastructure ───────────────────────────
    "dependency_enum": {
        "flag": "FLAG{D3P3ND3NCY_3NUM3R4T10N}",
        "difficulty": 1, "points": 100, "category": "recon",
        "module": "Administration",
        "description": "Dependency enumeration via API endpoint",
    },
    "verbose_error": {
        "flag": "FLAG{V3RB0S3_3RR0R_D1SCLOSUR3}",
        "difficulty": 1, "points": 100, "category": "recon",
        "module": "Administration",
        "description": "Verbose error message disclosure",
    },
    "zero_div_bypass": {
        "flag": "FLAG{Z3R0_D1V_BYPASS}",
        "difficulty": 2, "points": 200, "category": "logic",
        "module": "Administration",
        "description": "Division by zero bypass in calculator",
    },
    "integer_overflow": {
        "flag": "FLAG{1NT3G3R_0V3RFL0W}",
        "difficulty": 2, "points": 200, "category": "logic",
        "module": "Administration",
        "description": "Integer overflow in calculator",
    },
    "expired_coupon": {
        "flag": "FLAG{3XP1R3D_C0UP0N_V4L4R}",
        "difficulty": 2, "points": 200, "category": "logic",
        "module": "Marketplace",
        "description": "Expired coupon validation bypass",
    },
    "free_coupon_kinghand": {
        "flag": "FLAG{FR33_STUFF_K1NGH4ND}",
        "difficulty": 2, "points": 200, "category": "logic",
        "module": "Marketplace",
        "description": "100% discount coupon abuse",
    },
    "forged_review_identity": {
        "flag": "FLAG{F0RG3D_R3V13W_1D3NT1TY}",
        "difficulty": 3, "points": 300, "category": "auth",
        "module": "Marketplace",
        "description": "Forged identity in product review submission",
    },
    "negative_quantity": {
        "flag": "FLAG{N3G4T1V3_QTY_P4YB4CK}",
        "difficulty": 3, "points": 300, "category": "logic",
        "module": "Marketplace",
        "description": "Negative quantity exploit for credit payback",
    },
    # ── main.py flags ──
    "idor_order": {
        "flag": "FLAG{1D0R_15_345Y}",
        "difficulty": 2, "points": 200, "category": "auth",
        "module": "User Directory",
        "description": "IDOR in order lookup reveals admin order",
    },
    "ssti_payload": {
        "flag": "FLAG{5571_P4YL04D_C0NF1RM3D}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Data Import",
        "description": "Server-side template injection via render endpoint",
    },
    "lfi_master": {
        "flag": "FLAG{LFI_M4573R}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Data Import",
        "description": "Local file inclusion via path traversal in template",
    },
    "xxe_external": {
        "flag": "FLAG{XX3_3X73RN4L_3N717Y}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "Data Import",
        "description": "XXE external entity injection in XML parser",
    },
    "pickle_insecure": {
        "flag": "FLAG{P1CKL3_1N53CUR3}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "Data Import",
        "description": "Insecure deserialization via pickle in profile import",
    },
    "goad_sqli_union": {
        "flag": "FLAG{7H3_W4LL_H45_B33N_BR34CH3D}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "GOAD AD",
        "description": "UNION-based SQL injection in GOAD AD search",
    },
    "sqli_dump_users": {
        "flag": "FLAG{SQL1_DUM9_4LL_U53R5}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "GOAD AD",
        "description": "SQL injection dumping all user credentials",
    },
    # ── Shop product description flags (hidden in item data) ──
    "shop_dragonstone": {
        "flag": "FLAG{DR4G0N570N3_M1N3}",
        "difficulty": 1, "points": 100, "category": "recon",
        "module": "Marketplace",
        "description": "Hidden in Dragonstone Fortress product description",
    },
    "shop_intercepted_raven": {
        "flag": "FLAG{1NT3RC3PT3D_R4V3N}",
        "difficulty": 2, "points": 200, "category": "recon",
        "module": "Marketplace",
        "description": "Hidden in Raven Scroll product description",
    },
    "shop_harrenhal": {
        "flag": "FLAG{H4RR3NH4L_CURS3}",
        "difficulty": 2, "points": 200, "category": "recon",
        "module": "Marketplace",
        "description": "Hidden in Harrenhal product description",
    },
    "shop_valar_morghulis": {
        "flag": "FLAG{V4L4R_M0RGHUL1S}",
        "difficulty": 2, "points": 200, "category": "recon",
        "module": "Marketplace",
        "description": "Hidden in Jaqen's Kill List product description",
    },
    "shop_cme_warmap": {
        "flag": "FLAG{CME_W4R_M4P}",
        "difficulty": 2, "points": 200, "category": "recon",
        "module": "Marketplace",
        "description": "Hidden in CrackMapExec War Map product description",
    },
    # ── Deleted products (discoverable via SQLi) ──
    "deleted_product_rebellion": {
        "flag": "FLAG{D3L3T3D_PR0DUCT_R3B3LL10N}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Marketplace",
        "description": "Deleted product discoverable via SQL injection",
    },
    "deleted_product_ice_spear": {
        "flag": "FLAG{FR0Z3N_F1R3_D1SC0V3RY}",
        "difficulty": 3, "points": 300, "category": "injection",
        "module": "Marketplace",
        "description": "Deleted product discoverable via SQL injection",
    },
    # ── Checkout / payment flags ──
    "checkout_price_hack": {
        "flag": "FLAG{CH3CK0UT_PR1C3_H4CK}",
        "difficulty": 3, "points": 300, "category": "logic",
        "module": "Marketplace",
        "description": "Price manipulation at checkout",
    },
    "pci_violation_cc_leak": {
        "flag": "FLAG{PC1_V10L4T10N_CC_L34K}",
        "difficulty": 3, "points": 300, "category": "observability",
        "module": "Marketplace",
        "description": "PCI violation — credit card data in OTel traces",
    },
    "supply_chain_rce": {
        "flag": "FLAG{SUPPLY_CH41N_PLU61N_RCE}",
        "difficulty": 4, "points": 400, "category": "injection",
        "module": "System Console",
        "description": "Remote code execution via malicious plugin install",
    },
}


def validate_flag(submitted: str) -> dict | None:
    """Validate a submitted flag string. Returns metadata if correct, None if not."""
    for vuln_id, entry in FLAG_REGISTRY.items():
        if entry["flag"] == submitted:
            return {
                "vuln_id": vuln_id,
                "points": entry["points"],
                "category": entry["category"],
                "module": entry["module"],
                "description": entry["description"],
            }
    return None


def get_scoreboard() -> dict:
    """Return scoreboard summary stats."""
    total = len(FLAG_REGISTRY)
    categories = {}
    modules = {}
    total_points = 0
    for entry in FLAG_REGISTRY.values():
        cat = entry["category"]
        mod = entry["module"]
        categories[cat] = categories.get(cat, 0) + 1
        modules[mod] = modules.get(mod, 0) + 1
        total_points += entry["points"]
    return {
        "total_flags": total,
        "total_points": total_points,
        "categories": categories,
        "modules": modules,
    }
