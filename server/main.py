"""OCI Observability & Management Overview Server.

Enhanced vulnerable application mimicking Caldera attack patterns
for exfiltration and lateral movement testing.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import oci
from dotenv import load_dotenv
from fastapi import FastAPI, Request, File, UploadFile, Query
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

# APM OpenTelemetry Integration
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.pymssql import PyMSSQLInstrumentor
import pymssql
import httpx
import pickle
from lxml import etree

from .vulnerable_portal import router as portal_router
from .vulnerable_portal import MSSQL_SERVERS, GOAD_MSSQL_USER, GOAD_MSSQL_PASSWORD
from .shop_enhanced import router as enhanced_router

# Load environment variables from .env.local
load_dotenv(".env.local")

# Robust directory resolution
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "web" / "static"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Observability")

class Backend:
    """Handles OCI Observability Integration."""
    
    def __init__(self):
        self.config = None
        self.signer = None
        self.logging_client = None
        self.monitoring_client = None
        self.log_id = os.getenv("OCI_LOG_OCID")
        self.compartment_id = os.getenv("OCI_COMPARTMENT_OCID")
        self.namespace = os.getenv("OCI_MONITORING_NAMESPACE", "CustomAttackMetrics")

        try:
            self._init_oci_clients()
        except Exception as e:
            logger.error(f"Error initializing OCI clients: {e}")

    def _init_oci_clients(self):
        """Initialize OCI clients with 4-tier auth fallback."""
        auth_mode = os.getenv("OCI_AUTH_MODE", "").lower().replace("-", "_")
        signer_kwargs = {}
        config = {}

        # 1. Resource Principal
        if os.getenv("OCI_RESOURCE_PRINCIPAL_VERSION"):
            try:
                self.signer = oci.auth.signers.get_resource_principals_signer()
                signer_kwargs = {"signer": self.signer}
                logger.info("OCI auth: Resource Principal")
            except Exception as exc:
                logger.debug(f"Resource Principal failed: {exc}")

        # 2. Instance Principal
        if not signer_kwargs and auth_mode in ("instance_principal", "instanceprincipal", "auto"):
            try:
                self.signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                signer_kwargs = {"signer": self.signer}
                logger.info("OCI auth: Instance Principal")
            except Exception as exc:
                logger.debug(f"Instance Principal failed: {exc}")

        # 3. OCI config file
        if not signer_kwargs:
            try:
                profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
                config_file = os.path.expanduser(os.getenv("OCI_CONFIG_FILE", "~/.oci/config"))
                if os.path.exists(config_file):
                    config = oci.config.from_file(config_file, profile)
                    self.config = config
                    logger.info("OCI auth: Config file (profile=%s)", profile)
            except Exception as exc:
                logger.debug(f"Config file failed: {exc}")

        # 4. Environment variables
        if not signer_kwargs and not self.config:
            key_file = os.getenv("OCI_KEY_FILE")
            key_content = os.getenv("OCI_KEY_CONTENT")
            if key_file or key_content:
                try:
                    if key_file:
                        with open(os.path.expanduser(key_file)) as f:
                            key_pem = f.read()
                    else:
                        key_pem = key_content.replace("\\n", "\n")
                    config = {
                        "user": os.environ["OCI_USER_OCID"],
                        "key_content": key_pem,
                        "fingerprint": os.environ["OCI_FINGERPRINT"],
                        "tenancy": os.environ["OCI_TENANCY_OCID"],
                        "region": os.environ.get("OCI_REGION", ""),
                        "pass_phrase": os.getenv("OCI_KEY_PASSPHRASE", ""),
                    }
                    self.config = config
                    logger.info("OCI auth: Environment variables")
                except Exception as exc:
                    logger.debug(f"Env vars failed: {exc}")

        if not signer_kwargs and not self.config:
            logger.warning("No OCI auth method available. Running in simulation mode.")
            return

        self.logging_client = oci.loggingingestion.LoggingClient(config or {}, **signer_kwargs)
        self.monitoring_client = oci.monitoring.MonitoringClient(config or {}, **signer_kwargs)
        logger.info("OCI Observability clients initialized.")

    def push_log(self, type: str, message: str, metadata: dict[str, Any] = None):
        """Send a log entry to OCI Logging."""
        
        # OpenTelemetry Trace Context Injection for Log Correlation
        current_span = trace.get_current_span()
        span_context = current_span.get_span_context() if current_span else None
        
        if metadata is None:
            metadata = {}
            
        if span_context and span_context.is_valid:
            metadata["trace_id"] = trace.format_trace_id(span_context.trace_id)
            metadata["span_id"] = trace.format_span_id(span_context.span_id)

        entry = {
            "type": type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata
        }
        
        logger.info(f"[{type}] {message} (trace: {metadata.get('trace_id', 'none')})")
        
        if self.logging_client and self.log_id:
            try:
                log_content = oci.loggingingestion.models.LogEntryBatch(
                    entries=[oci.loggingingestion.models.LogEntry(
                        data=json.dumps(entry),
                        id=str(int(time.time() * 1000))
                    )],
                    source="ObservabilityApp",
                    type="com.oraclecloud.logging.custom.observability_overview",
                    default_log_entry_time=datetime.now(timezone.utc)
                )
                self.logging_client.put_logs(self.log_id, log_content)
            except Exception as e:
                logger.error(f"Failed to push log to OCI: {e}")

    def push_metric(self, name: str, value: float, dimensions: dict[str, str] = None):
        """Send a metric to OCI Monitoring."""
        if self.monitoring_client and self.compartment_id:
            try:
                metric_data = oci.monitoring.models.PostMetricDataDetails(
                    metric_data=[
                        oci.monitoring.models.MetricDataDetails(
                            namespace=self.namespace,
                            compartment_id=self.compartment_id,
                            name=name,
                            dimensions=dimensions or {"app": "Observability"},
                            datapoints=[
                                oci.monitoring.models.Datapoint(
                                    timestamp=datetime.now(timezone.utc),
                                    value=value
                                )
                            ]
                        )
                    ]
                )
                self.monitoring_client.post_metric_data(metric_data)
            except Exception as e:
                logger.error(f"Failed to push metric to OCI: {e}")

backend = Backend()

app = FastAPI(title="OCI Observability Overview")
app.add_middleware(GZipMiddleware, minimum_size=500)

# Setup OpenTelemetry APM Tracing
resource = Resource(attributes={"service.name": "SevenKingdomsApp"})
trace.set_tracer_provider(TracerProvider(resource=resource))
tracer_provider = trace.get_tracer_provider()

apm_endpoint = os.getenv("OCI_APM_ENDPOINT")
apm_private_key = os.getenv("OCI_APM_PRIVATE_DATAKEY")

if apm_endpoint and apm_private_key:
    # Build complete OTLP endpoint: typically {OCI_APM_ENDPOINT}/20200101/observations/public-span?dataFormat=otlp&dataFormatVersion=1.0&dataKey={PRIVATE_DATAKEY}
    # Handling typical bare APM endpoint formats in environment config
    otlp_endpoint = apm_endpoint.rstrip("/") + "/20200101/observations/public-span?dataFormat=otlp&dataFormatVersion=1.0&dataKey=" + apm_private_key
    
    otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
    tracer_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
    backend.push_log("SYSTEM", "OpenTelemetry initialized and routed to OCI APM via OTLP")
else:
    # Fallback to console export if APM is not fully configured
    tracer_provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    backend.push_log("SYSTEM", "OpenTelemetry running with Console Export (APM config missing)")

app.include_router(portal_router)
app.include_router(enhanced_router)

FastAPIInstrumentor.instrument_app(app)
PyMSSQLInstrumentor().instrument()

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    
    # Phase 4 Trace Enrichment: Add random user dimension for rich Log Analytics
    current_span = trace.get_current_span()
    got_users = ["jon.snow", "arya.stark", "tyrion.lannister", "daenerys.targaryen"]
    if current_span and current_span.is_recording():
        current_span.set_attribute("user.id", got_users[int(time.time()) % len(got_users)])
        current_span.set_attribute("client.ip", request.client.host)
        
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Custom metrics
    backend.push_metric("HttpRequest", 1.0, {
        "method": request.method,
        "path": request.url.path,
        "status_code": str(response.status_code)
    })
    
    return response

@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": "4.0.0-CALDERA-ENHANCED",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "static_dir": str(STATIC_DIR),
        "html_exists": (STATIC_DIR / "observability.html").exists()
    }

@app.get("/ready")
def ready() -> dict:
    """Readiness probe — checks dependencies are reachable."""
    checks = {"app": True}
    # OCI clients initialized?
    checks["oci_auth"] = backend.config is not None or backend.signer is not None
    # APM configured?
    checks["apm"] = bool(os.getenv("OCI_APM_ENDPOINT"))
    all_ok = checks["app"]  # App itself is always the gate
    return JSONResponse(
        content={"ready": all_ok, "checks": checks},
        status_code=200 if all_ok else 503,
    )

@app.get("/", response_class=HTMLResponse)
def index() -> str:
    html_file = STATIC_DIR / "observability.html"
    if not html_file.exists():
        return f"<h1>Error</h1><p>observability.html not found at {html_file}</p>"
    return html_file.read_text(encoding="utf-8")

@app.get("/vulnerable", response_class=HTMLResponse)
async def vulnerable_app() -> str:
    app_page = STATIC_DIR / "seven_kingdoms_app.html"
    if not app_page.exists():
        return HTMLResponse("<h1>Error</h1><p>Vulnerable app page not found.</p>", status_code=404)
    html = app_page.read_text(encoding="utf-8")

    # Inject APM endpoint and public key at serve-time so Browser RUM and the
    # OTel Web SDK initialise correctly.  The static HTML ships with empty strings
    # that are intentionally filled here from the runtime environment.
    apm_ep = os.getenv("OCI_APM_ENDPOINT", "")
    apm_pub = os.getenv("OCI_APM_PUBLIC_DATAKEY", "")
    if apm_ep and apm_pub:
        # Fill the inline window.apmrum config object (loaded before </body>)
        html = html.replace(
            'window.apmrum.ociDataUploadEndpoint = "";',
            f'window.apmrum.ociDataUploadEndpoint = "{apm_ep}";',
            1,
        )
        html = html.replace(
            'window.apmrum.OracleAPMPublicDataKey = "";',
            f'window.apmrum.OracleAPMPublicDataKey = "{apm_pub}";',
            1,
        )
        # Inject <meta> tags before </head> so the JS at page-bottom can also
        # read them via querySelector('meta[name="apm-endpoint"]')
        meta_tags = (
            f'  <meta name="apm-endpoint" content="{apm_ep}">\n'
            f'  <meta name="apm-public-key" content="{apm_pub}">\n'
        )
        html = html.replace("</head>", meta_tags + "  </head>", 1)
    return html

# --- UX DEGRADATION ENDPOINTS (referenced by seven_kingdoms_app.html) ---

@app.get("/app/slow-query")
async def ux_slow_query():
    """Simulates a slow database query (2-30s delay)."""
    tracer = trace.get_tracer(__name__)
    delay = random.uniform(2, 30)
    with tracer.start_as_current_span("db.slow_query", attributes={
        "db.system": "mssql", "db.statement": "SELECT * FROM large_table WHERE indexed=false",
        "db.duration_ms": delay * 1000, "ux.degradation": "slow_query",
    }):
        await asyncio.sleep(min(delay, 5))  # Cap actual sleep at 5s
        backend.push_metric("UXDegradation", 1.0, {"type": "slow_query", "delay_s": str(round(delay, 1))})
        return {"status": "degraded", "query_time_s": round(delay, 2), "threshold_breach": delay > 5}

@app.get("/app/error-page")
async def ux_error_page():
    """Triggers a simulated NullPointerException (HTTP 500)."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("app.unhandled_exception", attributes={
        "error": True, "exception.type": "NullPointerException",
        "exception.message": "Cannot read property 'orderId' of null",
        "ux.degradation": "application_error",
    }):
        backend.push_metric("UXDegradation", 1.0, {"type": "error_500"})
        return JSONResponse({"status": "error", "code": 500,
                            "exception": "NullPointerException: Cannot read property 'orderId' of null",
                            "stack_trace": "at OrderService.getOrder(OrderService.java:42)\nat OrderController.show(OrderController.java:18)"},
                           status_code=500)

@app.get("/app/cascade-failure")
async def ux_cascade_failure():
    """Simulates upstream service failure (HTTP 503)."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("circuit_breaker.open", attributes={
        "error": True, "http.status_code": 503,
        "upstream.service": "payment-service", "circuit_breaker.state": "OPEN",
        "ux.degradation": "cascade_failure",
    }):
        backend.push_metric("UXDegradation", 1.0, {"type": "cascade_503"})
        return JSONResponse({"status": "error", "code": 503,
                            "message": "Service Unavailable: payment-service circuit breaker OPEN",
                            "upstream_errors": ["payment-service: connection refused", "inventory-service: timeout"]},
                           status_code=503)

@app.get("/app/hard-load")
async def ux_hard_load():
    """Returns ~1MB HTML payload to simulate heavy page load."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("page.heavy_load", attributes={
        "http.response_content_length": 1048576, "ux.degradation": "heavy_page",
    }):
        # Generate ~1MB of HTML content
        chunk = "<div class='item'>" + "Lorem ipsum dolor sit amet. " * 20 + "</div>\n"
        body = "<html><body>" + chunk * 600 + "</body></html>"
        backend.push_metric("UXDegradation", 1.0, {"type": "heavy_page", "size_kb": str(len(body) // 1024)})
        return HTMLResponse(body)

@app.get("/app/timeout")
async def ux_timeout():
    """Simulates a request that hangs for 35 seconds."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("request.timeout", attributes={
        "ux.degradation": "timeout", "timeout_seconds": 35,
    }):
        backend.push_metric("UXDegradation", 1.0, {"type": "timeout"})
        await asyncio.sleep(35)
        return {"status": "completed", "elapsed": 35}

@app.get("/app/memory-pressure")
async def ux_memory_pressure():
    """Simulates GC pause / memory pressure."""
    tracer = trace.get_tracer(__name__)
    gc_pause = random.uniform(0.5, 5.0)
    heap_pct = random.randint(70, 95)
    with tracer.start_as_current_span("jvm.gc_pause", attributes={
        "jvm.gc.pause_ms": gc_pause * 1000, "jvm.memory.heap_used_pct": heap_pct,
        "ux.degradation": "memory_pressure",
    }):
        await asyncio.sleep(min(gc_pause, 2))
        backend.push_metric("UXDegradation", 1.0, {"type": "memory_pressure", "heap_pct": str(heap_pct)})
        return {"status": "degraded", "gc_pause_ms": round(gc_pause * 1000), "heap_used_pct": heap_pct}

@app.get("/app/intermittent-error")
async def ux_intermittent_error():
    """50% chance of failure - simulates flaky service."""
    tracer = trace.get_tracer(__name__)
    if random.random() < 0.5:
        with tracer.start_as_current_span("service.flaky_error", attributes={
            "error": True, "ux.degradation": "intermittent_error",
        }):
            backend.push_metric("UXDegradation", 1.0, {"type": "intermittent_error"})
            return JSONResponse({"status": "error", "message": "Connection reset by peer"}, status_code=503)
    return {"status": "success", "message": "Request succeeded (lucky 50%)"}

@app.get("/app/bad-gateway")
async def ux_bad_gateway():
    """Upstream returns invalid response (HTTP 502)."""
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("upstream.bad_gateway", attributes={
        "error": True, "http.status_code": 502,
        "upstream.service": "inventory-service",
        "ux.degradation": "bad_gateway",
    }):
        backend.push_metric("UXDegradation", 1.0, {"type": "bad_gateway"})
        return JSONResponse({"status": "error", "code": 502,
                            "message": "Bad Gateway: inventory-service returned malformed response"},
                           status_code=502)


# --- MITRE ATT&CK / CALDERA VULNERABILITIES ---

# 1. Exfiltration (T1041, T1048)
@app.post("/api/v1/exfiltration/upload")
async def exfiltrate_data(target_url: str, payload: str = "staged_data_chunk_001.zip"):
    """
    Simulates Exfiltration Over C2 Channel.
    In a real Caldera attack, the agent would upload data to a listener.
    """
    backend.push_log("SECURITY", f"EXFILTRATION: Data upload to {target_url}", {"payload": payload})
    backend.push_metric("ExfiltrationBytes", float(len(payload)), {"target": target_url})
    
    # Simulate a successful but suspicious upload
    async with httpx.AsyncClient() as client:
        try:
            # We don't actually hit the target to avoid spamming, but we log the attempt
            return {"status": "success", "bytes_sent": len(payload), "target": target_url}
        except Exception:
            return {"status": "mock_success", "bytes_sent": len(payload)}

@app.get("/api/v1/backup/export")
async def create_staged_backup(include_env: bool = True):
    """
    Simulates Archive Collected Data (T1560).
    Aggregates sensitive info into a 'backup' file for later exfiltration.
    """
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files": ["config.json", "users.db", "certs/private.key"],
        "size_mb": 42.5
    }
    if include_env:
        data["env_dump"] = base64.b64encode(b"OCI_TENANCY_OCID=ocid1.tenancy...").decode()
    
    backend.push_log("SECURITY", "COLLECTION: Sensitive data aggregated for backup", {"staged": True})
    backend.push_metric("CollectionEvents", 1.0)
    return data

# 2. Lateral Movement & Discovery (T1021, T1018, T1046)
@app.get("/api/v1/network/proxy")
async def network_proxy(url: str = Query(..., description="Internal URL to 'test' connectivity")):
    """
    Vulnerable to SSRF (Server-Side Request Forgery).
    Mimics Lateral Movement by allowing attackers to scan internal OCI networks.
    """
    backend.push_log("SECURITY", f"LATERAL_MOVEMENT: Internal network probe via SSRF: {url}")
    
    # Block obviously malicious external targets but allow internal ones to demonstrate vulnerability
    if "169.254.169.254" in url:
        backend.push_metric("AttackCount", 1.0, {"type": "SSRF_IMDS"})
        return {"error": "Access to IMDS metadata service blocked by security policy.", "blocked": True}
    
    try:
        # Simulate scanning internal host
        if "10.0." in url:
            backend.push_metric("InternalScanCount", 1.0)
            return {"status": "connected", "latency": "2ms", "target": url, "service": "SSH-2.0-OpenSSH_8.0"}
        
        return {"status": "error", "message": "Connection refused", "target": url}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# 3. Credential Access (T1555, T1552)
@app.get("/api/v1/auth/config")
async def get_auth_config():
    """
    Simulates Unsecured Credentials (T1552).
    Leaks mock API keys and configuration details.
    """
    backend.push_log("SECURITY", "DISCOVERY: Auth configuration accessed")
    return {
        "auth_method": "API_KEY",
        "region": os.getenv("OCI_REGION", "eu-frankfurt-1"),
        "debug_keys": {
            "OCI_ID_KEY": "----BEGIN PRIVATE KEY----MIIEvQ...",
            "DB_PASS": "WinterIsComing2024!"
        }
    }

# 4. Persistence (T1543)
@app.post("/api/v1/system/update")
async def update_system_service(service_name: str, exec_path: str):
    """
    Simulates Create or Modify System Process (T1543).
    Mimics an attacker creating a persistence mechanism.
    """
    backend.push_log("SECURITY", f"PERSISTENCE: System service modified: {service_name}", {"path": exec_path})
    backend.push_metric("PersistenceAlert", 1.0)
    
    if "/tmp/" in exec_path:
        return {"status": "error", "message": "ExecPath in /tmp/ is highly suspicious!", "detected": True}
    
    return {"status": "applied", "service": service_name}

# --- CTF CHALLENGE VULNERABILITIES ---

# CTF 1: IDOR (Insecure Direct Object Reference)
@app.get("/api/v1/ctf/orders/{order_id}")
async def get_order_details(order_id: int, request: Request):
    """
    Vulnerable to IDOR. Users can access other users' orders by guessing order_id.
    """
    tracer = trace.get_tracer(__name__)

    orders = {
        1001: {"user": "demo", "total": 150.00, "status": "shipped", "items": ["Sword"]},
        1002: {"user": "admin", "total": 9999.00, "status": "processing", "secret_note": "FLAG{1D0R_15_345Y}"},
    }

    with tracer.start_as_current_span("ctf.idor", attributes={
        "security.attack.type": "idor",
        "security.attack.severity": "high",
        "security.attack.owasp": "A01:2021",
        "security.attack.mitre_id": "T1078",
        "security.idor.order_id": order_id,
        "security.source_ip": request.client.host,
    }) as span:
        backend.push_log("SECURITY", f"CTF_IDOR: Accessed order {order_id}",
                         {"order_id": order_id, "source_ip": request.client.host})

        if order_id in orders:
            if order_id != 1001:
                span.set_attribute("security.flag_captured", True)
                backend.push_metric("CTFFlagFound", 1.0, {"type": "IDOR"})
            return {"status": "success", "data": orders[order_id]}

    return JSONResponse(status_code=404, content={"status": "error", "message": "Order not found"})

# CTF 2: SSTI / Path Traversal simulation
@app.get("/api/v1/ctf/render")
async def render_template(template: str, request: Request):
    """
    Simulates Server-Side Template Injection or Path Traversal.
    """
    tracer = trace.get_tracer(__name__)

    if "../" in template or "/etc/passwd" in template:
        with tracer.start_as_current_span("ctf.lfi", attributes={
            "security.attack.type": "lfi",
            "security.attack.severity": "critical",
            "security.attack.owasp": "A01:2021",
            "security.attack.mitre_id": "T1083",
            "security.attack.payload": template[:200],
            "security.source_ip": request.client.host,
        }) as span:
            span.set_attribute("security.flag_captured", True)
            backend.push_log("SECURITY", f"CTF_LFI: Path traversal with {template}")
            backend.push_metric("CTFFlagFound", 1.0, {"type": "LFI"})
            return {"status": "success", "rendered": "root:x:0:0:root:/root:/bin/bash\nFLAG{LFI_M4573R}"}

    if "{{" in template and "}}" in template:
        with tracer.start_as_current_span("ctf.ssti", attributes={
            "security.attack.type": "ssti",
            "security.attack.severity": "critical",
            "security.attack.owasp": "A03:2021",
            "security.attack.mitre_id": "T1190",
            "security.attack.payload": template[:200],
            "security.source_ip": request.client.host,
        }) as span:
            span.set_attribute("security.flag_captured", True)
            backend.push_log("SECURITY", f"CTF_SSTI: Template injection with {template}")
            backend.push_metric("CTFFlagFound", 1.0, {"type": "SSTI"})
            if "7*7" in template:
                return {"status": "success", "rendered": "49 - FLAG{5571_P4YL04D_C0NF1RM3D}"}
            return {"status": "success", "rendered": f"Template injected. FLAG{{5571_1NJ3C710N}}"}

    return {"status": "success", "rendered": f"Hello, {template}"}

# CTF 3: Reflected XSS
@app.get("/api/v1/ctf/search")
async def ctf_search(query: str, request: Request):
    """
    Simulates a Reflected XSS endpoint. Returns the query unescaped in HTML response.
    """
    tracer = trace.get_tracer(__name__)

    if "<script>" in query.lower() or "alert(" in query.lower():
        with tracer.start_as_current_span("ctf.xss", attributes={
            "security.attack.type": "xss",
            "security.attack.severity": "high",
            "security.attack.owasp": "A03:2021",
            "security.attack.mitre_id": "T1059.007",
            "security.attack.payload": query[:200],
            "security.source_ip": request.client.host,
        }) as span:
            span.set_attribute("security.flag_captured", True)
            backend.push_log("SECURITY", f"CTF_XSS: Reflected XSS with {query}")
            backend.push_metric("CTFFlagFound", 1.0, {"type": "XSS"})
            return HTMLResponse(content=f"<h3>Search results for: {query}</h3><p>No results found.</p><p style='color:green;'>FLAG{{X55_R3FL3C73D_W0RK5}}</p>", status_code=200)

    return HTMLResponse(content=f"<h3>Search results for: {query}</h3><p>No results found.</p>", status_code=200)

# CTF 4: XXE (XML External Entity)
@app.post("/api/v1/ctf/xml_upload")
async def xxe_upload(request: Request):
    """
    Simulates an XXE vulnerability. Uses lxml with resolve_entities=True.
    """
    tracer = trace.get_tracer(__name__)
    body = await request.body()

    with tracer.start_as_current_span("ctf.xxe", attributes={
        "security.attack.type": "xxe",
        "security.attack.severity": "critical",
        "security.attack.owasp": "A05:2021",
        "security.attack.mitre_id": "T1059",
        "security.xxe.payload_size": len(body),
        "security.source_ip": request.client.host,
    }) as span:
        backend.push_log("SECURITY", "CTF_XXE: Uploaded XML file.")

        try:
            parser = etree.XMLParser(resolve_entities=True, no_network=False)
            root = etree.fromstring(body, parser)

            extracted_content = ""
            for elem in root.iter():
                if elem.text and "root:x" in elem.text:
                    span.set_attribute("security.flag_captured", True)
                    backend.push_metric("CTFFlagFound", 1.0, {"type": "XXE"})
                    return {"status": "success", "message": "XML processed successfully.", "data": "Parsed successfully! FLAG{XX3_3X73RN4L_3N717Y}"}
                elif elem.text:
                    extracted_content += f"{elem.tag}: {elem.text}\n"

            # Even without /etc/passwd content, XXE attempt with DOCTYPE is suspicious
            if b"<!DOCTYPE" in body or b"<!ENTITY" in body:
                span.set_attribute("security.flag_captured", True)
                backend.push_metric("CTFFlagFound", 1.0, {"type": "XXE"})
                return {"status": "success", "message": "XML processed.", "data": extracted_content + "\nFLAG{XX3_3X73RN4L_3N717Y}"}

            return {"status": "success", "message": "XML processed.", "data": extracted_content}
        except Exception as e:
            return {"status": "error", "message": f"XML Parsing failed: {str(e)}"}

# CTF 5: Insecure Deserialization (Python Pickle)
@app.get("/api/v1/ctf/import_profile")
@app.post("/api/v1/ctf/import_profile")
async def import_profile(request: Request, payload: str = Query(..., description="Base64 encoded pickled profile")):
    """
    Simulates a Python Pickle deserialization vulnerability.
    Accepts both GET (from CTF UI) and POST (from curl).
    """
    tracer = trace.get_tracer(__name__)

    with tracer.start_as_current_span("ctf.deserialization", attributes={
        "security.attack.type": "deserialization",
        "security.attack.severity": "critical",
        "security.attack.owasp": "A08:2021",
        "security.attack.mitre_id": "T1059",
        "security.deserialization.payload_length": len(payload),
        "security.source_ip": request.client.host,
    }) as span:
        backend.push_log("SECURITY", "CTF_DESERIALIZATION: Profile import attempt")

        try:
            decoded = base64.b64decode(payload)

            if b"FLAG_INJECTED" in decoded or b"__reduce__" in decoded or b"system" in decoded:
                span.set_attribute("security.flag_captured", True)
                backend.push_metric("CTFFlagFound", 1.0, {"type": "DESERIALIZATION"})
                return {"status": "success", "profile": "Injected Code Execution simulated! FLAG{P1CKL3_1N53CUR3}"}

            obj = pickle.loads(decoded)
            return {"status": "success", "profile": str(obj)}

        except Exception as e:
            return {"status": "error", "message": f"Profile load failed: {str(e)}"}

# CTF 7: GOAD DB SQL Injection (The Wall)
@app.get("/api/v1/got/wildlings")
async def got_wildlings(name: str = "Tormund"):
    """
    Simulates a UNION-based SQL injection connecting to the GOAD castelblack DB.
    """
    got_tracer = trace.get_tracer("goad.wildlings")

    # ── Rich trace: wrap entire GOAD query flow ──
    with got_tracer.start_as_current_span("goad.wildling_search", attributes={
        "goad.search_name": name[:256],
        "goad.target_server": "castelblack",
    }) as search_span:

        backend.push_log("SECURITY", f"CTF_GOT_SQLI: Searching for wildling {name}")

        # Step 1: Analyze input
        with got_tracer.start_as_current_span("goad.analyze_input") as analyze_span:
            is_sqli = "UNION" in name.upper() and "SELECT" in name.upper()
            has_special = any(c in name for c in ["'", ";", "--", "/*"])
            analyze_span.set_attribute("goad.sqli_detected", is_sqli)
            analyze_span.set_attribute("goad.special_chars", has_special)
            if is_sqli:
                backend.push_metric("CTFFlagFound", 1.0, {"type": "SQLI_GOT"})

        # Step 2: Attempt real GOAD MSSQL connection
        srv = MSSQL_SERVERS.get("castelblack", {})
        conn = None
        try:
            with got_tracer.start_as_current_span("db.connect", attributes={
                "db.system": "mssql",
                "db.name": "master",
                "net.peer.name": srv.get("host", "192.168.56.22"),
                "net.peer.port": srv.get("port", 1433),
            }):
                conn = pymssql.connect(
                    server=srv.get("host", "192.168.56.22"),
                    user=GOAD_MSSQL_USER, password=GOAD_MSSQL_PASSWORD,
                    database="master", timeout=2,
                )

            with got_tracer.start_as_current_span("db.execute_query", attributes={
                "db.system": "mssql",
                "db.statement": f"SELECT * FROM wildlings WHERE name = '{name}'"[:512],
            }):
                cursor = conn.cursor()
                cursor.execute(f"SELECT * FROM wildlings WHERE name = '{name}'")
                row = cursor.fetchone()

            search_span.set_attribute("goad.result_source", "live_mssql")
            return {"status": "success", "data": row if row else "No wildling found."}

        except Exception as e:
            # Step 3: Fallback simulation
            with got_tracer.start_as_current_span("db.simulated_query", attributes={
                "db.system": "mssql",
                "db.name": "master",
                "db.statement": f"SELECT * FROM wildlings WHERE name = '{name}'"[:512],
                "net.peer.name": "castelblack.north.sevenkingdoms.local",
                "net.peer.port": 1433,
                "db.simulated": True,
            }) as sim_span:
                if is_sqli:
                    sim_span.set_attribute("security.attack.type", "sqli")
                    sim_span.set_attribute("security.attack.severity", "critical")
                    sim_span.set_attribute("security.attack.mitre_id", "T1190")
                    sim_span.set_attribute("security.attack.payload", name[:200])
                    sim_span.set_attribute("security.attack.detected", True)
                    search_span.set_attribute("goad.result_source", "simulated")
                    return {"status": "success", "data": "UNION result simulated! FLAG{7H3_W4LL_H45_B33N_BR34CH3D}"}

                search_span.set_attribute("goad.result_source", "error")
                return {"status": "error", "message": f"Wildling not found (DB Error): {str(e)}"}
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

# CTF 8: SSRF to Meereen (Dragon Eggs)
@app.get("/api/v1/got/dragons")
async def got_dragons(request: Request, url: str = "http://meereen.essos.local/api/dragon_locations"):
    """
    Simulates a Server-Side Request Forgery fetching internal resources.
    """
    backend.push_log("SECURITY", f"CTF_GOT_SSRF: Fetching dragon eggs from {url}")
    tracer = trace.get_tracer(__name__)
    
    is_ssrf = "169.254.169.254" in url or "meereen" in url or "10.0." in url or "192.168." in url
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(url)
            if is_ssrf:
                # SSRF succeeded — the app fetched an internal resource
                with tracer.start_as_current_span("ctf.ssrf", attributes={
                    "security.attack.type": "ssrf",
                    "security.attack.severity": "critical",
                    "security.attack.owasp": "A10:2021",
                    "security.attack.mitre_id": "T1090",
                    "security.ssrf.target_url": url,
                    "security.ssrf.response_code": resp.status_code,
                    "security.source_ip": request.client.host,
                    "security.flag_captured": True,
                }) as span:
                    backend.push_metric("CTFFlagFound", 1.0, {"type": "SSRF_GOT"})
                    return {"status": "success", "ssrf_response": resp.text[:500], "flag": "FLAG{M07H3R_0F_DR4G0N5_55RF}"}
            return {"status": "success", "data": resp.text}
    except Exception as e:
        # Fallback trace generation for SSRF simulation when target unreachable
        if is_ssrf:
            backend.push_metric("CTFFlagFound", 1.0, {"type": "SSRF_GOT"})
            with tracer.start_as_current_span(
                "HTTP GET",
                attributes={
                    "http.method": "GET",
                    "http.url": url,
                    "net.peer.name": "meereen.essos.local",
                    "security.attack.type": "ssrf",
                    "security.attack.severity": "critical",
                    "security.attack.owasp": "A10:2021",
                    "security.attack.mitre_id": "T1090",
                    "security.ssrf.target_url": url,
                    "security.source_ip": request.client.host,
                }
            ) as span:
                span.set_attribute("security.flag_captured", True)
                return {"status": "success", "data": "Internal Network accessed realistically! FLAG{M07H3R_0F_DR4G0N5_55RF}"}

        return {"status": "error", "message": f"Failed to fetch dragon eggs: {str(e)}"}

# --- Legacy Vulnerabilities (Retained for Compatibility) ---

@app.get("/api/v1/users/search")
async def search_users(q: str, request: Request):
    """Vulnerable to SQL Injection."""
    tracer = trace.get_tracer(__name__)

    if "'" in q or "--" in q or "UNION" in q.upper() or "1=1" in q:
        with tracer.start_as_current_span("ctf.sqli", attributes={
            "security.attack.type": "sqli",
            "security.attack.severity": "critical",
            "security.attack.owasp": "A03:2021",
            "security.attack.mitre_id": "T1190",
            "security.attack.payload": q[:200],
            "security.source_ip": request.client.host,
            "db.system": "sqlite",
            "db.statement": f"SELECT * FROM users WHERE name = '{q}'",
        }) as span:
            span.set_attribute("security.flag_captured", True)
            backend.push_log("SECURITY", f"CTF_SQLI: SQL Injection with {q}")
            backend.push_metric("CTFFlagFound", 1.0, {"type": "SQLi"})
            return {
                "error": f"SQL Syntax Error near '{q}'",
                "exploited": True,
                "leaked_data": [
                    {"username": "admin", "password_hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
                    {"username": "jon.snow", "password_hash": "e10adc3949ba59abbe56e057f20f883e"},
                    {"username": "cersei", "password_hash": "FLAG{SQL1_DUM9_4LL_U53R5}"},
                ]
            }
    return {"results": [{"user": "admin"}, {"user": "demo"}]}

@app.get("/api/v1/system/diagnostics")
async def system_diag(cmd: str, request: Request):
    """Vulnerable to Command Injection."""
    tracer = trace.get_tracer(__name__)

    if ";" in cmd or "|" in cmd or "whoami" in cmd or "cat " in cmd:
        with tracer.start_as_current_span("ctf.rce", attributes={
            "security.attack.type": "rce",
            "security.attack.severity": "critical",
            "security.attack.owasp": "A03:2021",
            "security.attack.mitre_id": "T1059",
            "security.attack.payload": cmd[:200],
            "security.source_ip": request.client.host,
        }) as span:
            span.set_attribute("security.flag_captured", True)
            backend.push_log("SECURITY", f"CTF_RCE: Command injection with {cmd}")
            backend.push_metric("CTFFlagFound", 1.0, {"type": "RCE"})
            return {
                "output": f"$ {cmd}\nuid=1000(appuser) gid=1000(appgroup) groups=1000(appgroup)\nappuser\nFLAG{{RC3_G4M3_0V3R}}"
            }
    return {"output": f"Executing: {cmd}\nOutput: Simulated success."}

# Mount static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
