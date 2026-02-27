# Seven Kingdoms Portal

A deliberately vulnerable web application themed around Game of Thrones, designed for **security training**, **OCI Observability demonstrations**, and **CTF-style challenges**. Built with FastAPI and vanilla JS, fully instrumented with OpenTelemetry for attack detection via OCI APM and Log Analytics.

> **Warning**: This application contains intentional security vulnerabilities. Deploy only in isolated lab environments.

## What is this?

Seven Kingdoms Portal is a "GOAD-style" (Game of Active Directory) web application that provides:

- **30 intentional vulnerabilities** across OWASP Top 10 categories (SQLi, XSS, SSRF, IDOR, RCE, SSTI, etc.)
- **20 detection rules** with pre-built APM + Log Analytics queries
- **Full OpenTelemetry instrumentation** — every attack generates traces with security-specific span attributes
- **OCI Observability integration** — APM, Log Analytics, Monitoring, custom metrics
- **Interactive attack runner** — trigger vulnerabilities from the UI and see them detected in real-time

## Features

### Security / CTF
- **Vulnerability Scenarios**: IDOR, Path Traversal, SQLi, XSS, SSRF, RCE, SSTI, LDAP Injection, Deserialization, JWT manipulation, Kerberoasting, DCSync simulation
- **Detection Rules Tab**: Browse all 20 detection rules with copy-to-clipboard APM/LA queries
- **Attack Runner**: Execute attack chains directly from the portal UI
- **Activity Feed**: Real-time log of all security events
- **GOAD Integration**: Kerberoasting and DCSync attacks against Active Directory lab

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
| `/health` | Liveness probe — app vitality |
| `/ready` | Readiness probe — dependency checks |
| `/portal/` | Seven Kingdoms Portal UI |
| `/portal/api/detection-rules` | Detection rules API |
| `/` | OCI Observability Overview dashboard |

## Environment Variables

See [`.env.local.example`](.env.local.example) for the full list. Key variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `APP_PORT` | Application port | `9010` |
| `APP_WORKERS` | Uvicorn worker count | `4` |
| `ENVIRONMENT` | Runtime environment | `development` |
| `OCI_AUTH_MODE` | OCI SDK auth method | `instance_principal` |
| `OCI_APM_ENDPOINT` | APM collector endpoint | — |
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

## License

MIT

## Acknowledgments

- Inspired by [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (Game of Active Directory)
- Built for [OCI](https://www.oracle.com/cloud/) Observability & Security demonstrations
