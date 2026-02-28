# Seven Kingdoms Portal

A deliberately vulnerable web application themed around Game of Thrones, designed for **security training**, **OCI Observability demonstrations**, and **CTF-style challenges**. Built with FastAPI and vanilla JS, fully instrumented with OpenTelemetry for attack detection via OCI APM and Log Analytics.

> **Warning**: This application contains intentional security vulnerabilities. Deploy only in isolated lab environments.

## Deploy to Oracle Cloud

[![Deploy to Oracle Cloud](https://oci-resourcemanager-plugin.plugins.oci.oraclecloud.com/latest/deploy-to-oracle-cloud.svg)](https://cloud.oracle.com/resourcemanager/stacks/create?zipUrl=https://github.com/adibirzu/seven-kingdoms-portal/archive/refs/heads/main.zip)

> Set **Working Directory** to `stack/` when creating the stack. This deploys the complete platform: VCN, OKE cluster, GOAD Active Directory lab (optional), observability, WAF, and the vulnerable app — all automatically orchestrated.

## Screenshots

### Dashboard
The Kingdom Overview shows real-time stats: 30 vulnerabilities, 10 OWASP categories, 3 GOAD domains. The Quick Attack Panel lets you trigger critical attacks (SQLi, RCE, SSRF, Path Traversal, JWT bypass, Crypto leak) with one click.

![Dashboard](docs/screenshots/02-dashboard.png)

### Attack Encyclopedia (Learn Tab)
Comprehensive educational guide to every vulnerability. Each entry documents how the attack works, what OpenTelemetry span attributes are generated, and how to detect it in OCI APM and Log Analytics.

![Learn Overview](docs/screenshots/07-learn-overview.png)

Expand any attack for step-by-step exploitation walkthrough, example payloads, real-world impact, and MITRE ATT&CK mapping:

![Attack Detail](docs/screenshots/09-learn-attack-detail.png)

Each attack includes side-by-side detection queries for OCI APM Trace Explorer and OCI Log Analytics, with copy-to-clipboard buttons:

![Detection Queries](docs/screenshots/10-learn-detection-queries.png)

### Detection Rules
Browse all 20 detection rules with severity badges, MITRE technique IDs, OWASP categories, and one-click query copying:

![Detections](docs/screenshots/11-detections.png)

### Login
Game of Thrones themed login with multiple user accounts and domain authentication (for GOAD Active Directory integration):

![Login](docs/screenshots/01-login.png)

### CTF Platform (`/vulnerable`)
Full capture-the-flag interface with 18 challenges across Web Application Attacks, GOAD Active Directory Attacks, and UX Degradation Scenarios. Each challenge card shows OWASP category, severity badge, endpoint, and OTel instrumentation status.

![CTF Challenges](docs/screenshots/ctf-01-challenges.png)

GOAD integration: Mission 7 (MSSQL Injection) and Mission 8 (SSRF) target the Active Directory lab. UX scenarios generate APM traces for observability demonstrations:

![GOAD & UX Scenarios](docs/screenshots/ctf-02-goad.png)

Click any challenge to fire the attack — the response panel shows HTTP status, latency, and auto-extracts flags via regex:

![Challenge Response](docs/screenshots/ctf-03-response.png)

### CTF Walkthrough Guides
Step-by-step exploitation guides with curl commands, expected output, and OCI APM detection queries:

![Walkthrough Guide](docs/screenshots/ctf-04-walkthrough.png)

Expand any guide for the full attack flow — from understanding the target to detecting the attack in OCI APM Trace Explorer:

![Expanded Walkthrough](docs/screenshots/ctf-05-walkthrough-expanded.png)

## What is this?

Seven Kingdoms Portal is a "GOAD-style" (Game of Active Directory) web application that provides:

- **60+ intentional vulnerabilities** across OWASP Top 10 categories (SQLi, XSS, SSRF, IDOR, RCE, SSTI, XXE, CSRF, price tampering, coupon forgery, prototype pollution, etc.)
- **Enhanced Marketplace** — Juice Shop-inspired e-commerce tab with 15+ exploitable business logic vulnerabilities
- **32 attack entries** in the Attack Encyclopedia with educational walkthroughs
- **30 detection rules** with pre-built APM + Log Analytics queries
- **Full OpenTelemetry instrumentation** — every attack generates traces with security-specific span attributes (`security.attack.*`, `app.runtime`, `app.service`)
- **Runtime-aware APM** — service names distinguish deployments: `seven-kingdoms-portal-oke`, `seven-kingdoms-portal-vm`
- **OCI Observability integration** — APM, Log Analytics, Monitoring, custom metrics
- **Interactive attack runner** — trigger vulnerabilities from the UI and see them detected in real-time

## How Attacks Work

### Attack Flow
```
User triggers attack (UI or API)
  → FastAPI endpoint processes malicious input
  → OpenTelemetry span records security attributes
  → OCI APM receives the trace
  → Detection rules match span attributes
  → Alert fires in OCI Monitoring
```

### Example: SQL Injection (A03)

1. **Attack**: User sends `' UNION SELECT username, password FROM users--` to the treasury search
2. **OTel Span**: Sets `security.attack.type=sqli`, `security.attack.severity=critical`, `security.sqli.payload=...`
3. **APM Detection**: `show (spans) where SpanAttribute['security.attack.type'] = 'sqli'`
4. **LA Detection**: `'Log Source' = 'OCI APM Trace' | where security_attack_type = 'sqli' | stats count by security_source_ip`

### Example: Kerberoasting (GOAD)

1. **Attack**: Portal sends Kerberoasting request to GOAD domain controller
2. **OTel Span**: Sets `security.attack.type=kerberoast`, `security.goad.target_domain=sevenkingdoms.local`
3. **APM Detection**: Filter spans where `security.attack.type = 'kerberoast'`
4. **Windows Event**: Event ID 4769 (TGS request with RC4 encryption) in domain controller logs

## OWASP Categories Covered

| Category | Attacks | Examples |
|----------|---------|----------|
| A01: Broken Access Control | 6 | IDOR, Path Traversal, Open Redirect, Admin Panel, Privilege Escalation, CSRF Allegiance |
| A02: Cryptographic Failures | 3 | Config Exposure, MD5 Hashes, Coupon Forgery (weak encoding) |
| A03: Injection | 7 | SQLi, RCE, SSTI, LDAP Injection, Stored XSS, XXE, Prototype Pollution |
| A04: Insecure Design | 5 | Mass Assignment, Negative Transfer, Negative Quantity, Price Tampering, Expired Coupon Reuse |
| A05: Security Misconfiguration | 3 | Env Exposure, Score Board Discovery, Hidden Endpoints |
| A07: Auth Failures | 5 | JWT None, Default Creds, Session Fixation, CAPTCHA Bypass, Security Question Bypass |
| A08: Integrity Failures | 1 | Pickle Deserialization |
| A09: Logging Failures | 2 | Silent Transfer, Log Injection |
| A10: SSRF | 1 | Cloud IMDS Metadata Access |
| GOAD (AD Attacks) | 2 | Kerberoasting, DCSync |

## Features

### Security / CTF
- **Attack Encyclopedia**: Educational walkthrough for every vulnerability with step-by-step exploitation, OTel attributes, and detection queries
- **Detection Rules Tab**: Browse all 20 detection rules with copy-to-clipboard APM/LA queries
- **Attack Runner**: Execute all 30 attacks sequentially to generate APM traces
- **Activity Feed**: Real-time log of all security events
- **CTF Scoreboard**: Flag-based scoring across all vulnerability categories
- **GOAD Integration**: Kerberoasting and DCSync attacks against Active Directory lab

### Enhanced Marketplace (Shop Tab)
Juice Shop-inspired e-commerce platform with 60 products across 7 houses and 15+ exploitable endpoints:
- **Product Reviews**: Stored XSS and forged identity attacks
- **Coupon System**: Weak base64 encoding, expired coupon reuse, forged discount codes
- **Gold Wallet**: Negative transfers, IDOR between users, race conditions
- **Trade Import**: XXE injection via XML payload parsing
- **Allegiance Change**: CSRF — change a user's house without proper token validation
- **Security Questions**: OSINT-based password reset bypass
- **Admin Registration**: Hidden `role` parameter in registration endpoint
- **CAPTCHA Bypass**: Predictable math challenges with `answer=0` bypass
- **Score Board**: Hidden endpoint discovery (security through obscurity)
- **Purchase System**: Negative quantity and price tampering attacks
- **Prototype Pollution**: `__proto__` injection via config update endpoint
- **Deleted Products**: Hidden inventory endpoint exposing removed items
- **Admin Panel**: Unauthenticated admin access

### OCI Observability Overview
- **Command Center**: Unified view of all OCI O&M services
- **Service Modules**: Log Analytics, APM, Ops Insights, Database Management, and more
- **Interactive Mindmap**: Visual service relationship explorer
- **OCI Monitoring Query Builder**: MQL generation tool
- **AI Chat Assistant**: OCI Observability Q&A
- **Dark/Light/Redwood Themes**: Multiple theme support with glassmorphism effects

### Deployment
- **Multi-infrastructure**: VM, Docker, OCI Container Instances, OKE (Kubernetes)
- **12-Factor Config**: All settings via environment variables — no baked-in config files
- **Terraform IaC**: Full OCI infrastructure (VCN, Compute, LB, WAF, DNS)
- **Kustomize Overlays**: Dev/prod Kubernetes configurations

## Quick Start

### Local Development

```bash
python -m venv .venv
source .venv/activate
pip install -r requirements.txt
./scripts/start.sh
# Open http://127.0.0.1:9010
```

### Docker

```bash
# Copy and configure environment
cp .env.local.example .env.local

# Build and run
cd deploy/docker
docker compose up -d

# Check health
curl http://localhost:9010/health
```

### Deploy to OCI (VM)

```bash
# 1. Configure terraform variables
cd deploy/terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your OCI credentials

# 2. Deploy infrastructure
cd deploy && ./scripts/deploy.sh --environment prod --mode vm

# 3. Deploy application
export SSH_KEY=~/.ssh/your_private_key
./scripts/deploy-app.sh --mode vm --environment prod

# 4. Verify
curl http://$(terraform output -raw lb_public_ip)/health
```

### Deploy to OKE (Kubernetes)

```bash
./scripts/deploy-app.sh --mode oke \
  --registry fra.ocir.io/namespace \
  --tag v1.0.0
```

### Deploy to OCI Container Instance

```bash
./scripts/deploy-app.sh --mode container-instance \
  --registry fra.ocir.io/namespace \
  --tag v1.0.0
```

## Architecture

```
Internet → WAF → Load Balancer (public subnet) → App VM (private subnet, port 9010)
                  Bastion (public subnet) ──SSH──► App VM (port 22)
```

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health` | Liveness probe — runtime, service name, APM status |
| `/ready` | Readiness probe — dependency checks |
| `/portal/` | Seven Kingdoms Portal UI (Dashboard, Learn, Detections, Shop) |
| `/portal/api/detection-rules` | Detection rules API |
| `/portal/api/score-board` | CTF score board (hidden discovery challenge) |
| `/portal/api/shop/reviews/{id}` | Product reviews — stored XSS, forged identity |
| `/portal/api/shop/coupon/apply` | Coupon system — forgery, expired reuse |
| `/portal/api/wallet/transfer` | Gold wallet — negative transfers, IDOR |
| `/portal/api/trade/import` | Trade import — XXE injection |
| `/portal/api/shop/purchase-enhanced` | Purchase — negative quantity, price tampering |
| `/portal/api/config/update` | Config — prototype pollution |
| `/portal/api/shop/admin-panel` | Admin panel — unauthenticated access |
| `/vulnerable` | CTF platform — challenges, walkthroughs, scoreboard |
| `/` | OCI Observability Overview dashboard |

## Environment Variables

See [`.env.local.example`](.env.local.example) for the full list. Key variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `APP_PORT` | Application port | `9010` |
| `APP_WORKERS` | Uvicorn worker count | `4` |
| `APP_RUNTIME` | Deployment runtime (`vm`, `oke`, `docker`) | `unknown` |
| `APP_SERVICE_NAME` | Override APM service name | `seven-kingdoms-portal-{APP_RUNTIME}` |
| `ENVIRONMENT` | Runtime environment | `development` |
| `OCI_AUTH_MODE` | OCI SDK auth method | `instance_principal` |
| `OCI_APM_ENDPOINT` | APM domain base URL | — |
| `OCI_APM_PRIVATE_DATAKEY` | APM private data key for OTLP auth | — |
| `PORTAL_JWT_SECRET` | JWT signing secret | random |

## Detection Rules

All 20 rules map to MITRE ATT&CK techniques and OWASP Top 10 categories:

| ID | Attack | Severity | MITRE | OWASP |
|----|--------|----------|-------|-------|
| SKP-001 | IDOR | High | T1078 | A01:2021 |
| SKP-002 | Path Traversal | Critical | T1083 | A01:2021 |
| SKP-005 | SQL Injection | Critical | T1190 | A03:2021 |
| SKP-006 | Command Injection | Critical | T1059 | A03:2021 |
| SKP-009 | Stored XSS | High | T1059.007 | A03:2021 |
| SKP-017 | SSRF | Critical | T1090 | A10:2021 |
| SKP-018 | Kerberoasting | Critical | T1558.003 | N/A |
| ... | [+13 more](server/detection_rules.py) | | | |

## Re-generating Screenshots

```bash
npm install
node docs/take-screenshots.mjs      # Portal screenshots
node docs/take-ctf-screenshots.mjs   # CTF platform screenshots
```

## Legal Disclaimer

> **This is a personal educational project.** It has **no affiliation with Oracle Corporation, HBO, George R.R. Martin, or Penguin Random House**.

- **"A Song of Ice and Fire"** is a novel series by George R.R. Martin, published by Bantam Books (Penguin Random House). All book content is copyright of the author.
- **"Game of Thrones"** is a registered trademark of Home Box Office, Inc. (HBO). All character names, locations, house sigils, and lore referenced in this project are the intellectual property of their respective owners.
- This project uses thematic elements under **fair use** for **non-commercial, educational purposes only** — specifically cybersecurity training and observability demonstrations.
- The Game of Thrones / medieval fantasy theming follows the convention established by [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD), the open-source Active Directory lab by Orange Cyberdefense that this project integrates with.
- Any reference to Oracle Cloud Infrastructure (OCI) relates solely to the cloud environment used for lab deployment and does not imply endorsement or affiliation.

## License

MIT — see [LICENSE](LICENSE)

## Acknowledgments

- Inspired by [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (Game of Active Directory) by Orange Cyberdefense
- Built for [OCI](https://www.oracle.com/cloud/) Observability & Security demonstrations
- GoT thematic elements are used for educational purposes consistent with GOAD's naming conventions
