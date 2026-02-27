/**
 * OCI Observability & Management Platform
 * Interactive Presentation Application
 */

(function() {
    'use strict';

    // ============================================
    // State Management
    // ============================================
    const state = {
        currentModule: 'home',
        currentUseCase: 'lost-order',
        cloudGuardMode: 'free',
        selectedCluster: null,
        animationFrameId: null,
        theme: localStorage.getItem('oci-theme') || 'dark'
    };

    // ============================================
    // DOM Elements Cache
    // ============================================
    const elements = {
        navItems: null,
        modules: null,
        useCaseTabs: null,
        useCaseContents: null,
        cloudGuardToggle: null,
        securityHalo: null,
        mindmap: null,
        connectionLines: null
    };

    // ============================================
    // Initialization
    // ============================================
    function init() {
        cacheElements();
        bindEvents();
        initMindmapConnections();
        initAnimations();
        initCounters();
        initTheme();
        initTierToggle();
        /* Platform initialized */
    }

    // ============================================
    // Theme Management
    // ============================================
    function initTheme() {
        // Apply saved theme on load
        const savedTheme = localStorage.getItem('oci-theme') || 'dark';
        state.theme = savedTheme;
        applyTheme(savedTheme);

        // Bind theme options
        const themeOptions = document.getElementById('themeOptions');
        if (themeOptions) {
            themeOptions.querySelectorAll('.theme-option').forEach(option => {
                option.addEventListener('click', () => {
                    const theme = option.dataset.theme;
                    setTheme(theme);
                });
            });
        }

        // Also keep the old toggle working
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', toggleThemeLegacy);
        }
    }

    function setTheme(theme) {
        state.theme = theme;
        applyTheme(theme);
        localStorage.setItem('oci-theme', theme);

        // Update active button
        const themeOptions = document.getElementById('themeOptions');
        if (themeOptions) {
            themeOptions.querySelectorAll('.theme-option').forEach(opt => {
                opt.classList.toggle('active', opt.dataset.theme === theme);
            });
        }
    }

    function applyTheme(theme) {
        if (theme === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
        } else if (theme === 'redwood') {
            document.documentElement.setAttribute('data-theme', 'redwood');
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
    }

    function toggleThemeLegacy() {
        if (state.theme === 'dark') {
            setTheme('light');
        } else {
            setTheme('dark');
        }
    }

    // ============================================
    // Tier Toggle Management
    // ============================================
    function initTierToggle() {
        const tierToggle = document.getElementById('tierToggle');
        if (!tierToggle) return;

        // Load saved tier
        const savedTier = localStorage.getItem('oci-tier') || 'free';
        state.tier = savedTier;
        applyTier(savedTier);

        // Update toggle UI
        tierToggle.dataset.value = savedTier;
        tierToggle.querySelectorAll('.toggle-option').forEach(opt => {
            opt.classList.toggle('active', opt.dataset.value === savedTier);
        });

        // Bind events
        tierToggle.querySelectorAll('.toggle-option').forEach(option => {
            option.addEventListener('click', () => {
                const tier = option.dataset.value;
                setTier(tier);
            });
        });
    }

    function setTier(tier) {
        state.tier = tier;
        applyTier(tier);
        localStorage.setItem('oci-tier', tier);

        // Update toggle UI
        const tierToggle = document.getElementById('tierToggle');
        if (tierToggle) {
            tierToggle.dataset.value = tier;
            tierToggle.querySelectorAll('.toggle-option').forEach(opt => {
                opt.classList.toggle('active', opt.dataset.value === tier);
            });
        }
    }

    function applyTier(tier) {
        document.documentElement.setAttribute('data-tier', tier);

        // Update visibility of tier-specific content (feature tags)
        document.querySelectorAll('[data-tier-required]').forEach(el => {
            const required = el.dataset.tierRequired;
            if (required === 'paid' && tier === 'free') {
                el.classList.add('tier-locked');
            } else {
                el.classList.remove('tier-locked');
            }
        });

        // Update tier badges visibility in service card headers
        document.querySelectorAll('.tier-badges .tier-badge').forEach(el => {
            const badgeType = el.classList.contains('free') ? 'free' :
                              el.classList.contains('paid') ? 'paid' : 'enterprise';
            // Show relevant badges based on selected tier
            if (tier === 'free') {
                el.style.display = (badgeType === 'free' || badgeType === 'enterprise') ? 'inline-flex' : 'none';
            } else {
                el.style.display = (badgeType === 'paid' || badgeType === 'enterprise') ? 'inline-flex' : 'none';
            }
        });

        // Note: Capability rows use CSS opacity based on [data-tier] attribute
        // No JS manipulation needed - CSS handles the visual differentiation
    }

    function cacheElements() {
        elements.navItems = document.querySelectorAll('.nav-item');
        elements.modules = document.querySelectorAll('.module');
        elements.useCaseTabs = document.querySelectorAll('.use-case-tab');
        elements.useCaseContents = document.querySelectorAll('.use-case-content');
        elements.cloudGuardToggle = document.getElementById('cloudGuardToggle');
        elements.securityHalo = document.getElementById('securityHalo');
        elements.mindmap = document.getElementById('mindmap');
        elements.connectionLines = document.getElementById('connectionLines');
    }

    // ============================================
    // Event Bindings
    // ============================================
    function bindEvents() {
        // Navigation
        elements.navItems.forEach(item => {
            item.addEventListener('click', handleNavClick);
        });

        // Use Case Tabs
        elements.useCaseTabs.forEach(tab => {
            tab.addEventListener('click', handleUseCaseClick);
        });

        // Cloud Guard Toggle
        if (elements.cloudGuardToggle) {
            const options = elements.cloudGuardToggle.querySelectorAll('.toggle-option');
            options.forEach(option => {
                option.addEventListener('click', handleCloudGuardToggle);
            });
        }

        // Pillar nodes click - navigate to module
        document.querySelectorAll('.pillar-node').forEach(node => {
            node.addEventListener('click', handlePillarClick);
        });

        // Cluster bubbles
        document.querySelectorAll('.cluster-bubble').forEach(bubble => {
            bubble.addEventListener('click', handleClusterClick);
        });

        // Brazil marker on map
        const brazilMarker = document.getElementById('brazilMarker');
        if (brazilMarker) {
            brazilMarker.addEventListener('click', handleBrazilClick);
        }

        // Stuck job click
        const stuckJob = document.getElementById('stuckJob');
        if (stuckJob) {
            stuckJob.addEventListener('click', handleStuckJobClick);
        }

        // Query suggestions
        document.querySelectorAll('.suggestion-chip').forEach(chip => {
            chip.addEventListener('click', handleSuggestionClick);
        });

        // Quick prompts for AI
        document.querySelectorAll('.prompt-chip').forEach(chip => {
            chip.addEventListener('click', handlePromptClick);
        });

        // View toggle buttons
        document.querySelectorAll('.view-btn').forEach(btn => {
            btn.addEventListener('click', handleViewToggle);
        });

        // Window resize for mindmap connections
        window.addEventListener('resize', debounce(initMindmapConnections, 250));
    }

    // ============================================
    // Navigation Handlers
    // ============================================
    function handleNavClick(e) {
        const item = e.currentTarget;
        const module = item.dataset.module;

        // Special handling for Vulnerable App (External Redirect)
        if (module === 'sevenkingdoms') {
            window.location.href = '/vulnerable';
            return;
        }

        if (module === state.currentModule) return;

        // Update nav state
        elements.navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        // Update module visibility
        elements.modules.forEach(mod => mod.classList.remove('active'));
        const targetModule = document.getElementById(`module-${module}`);
        if (targetModule) {
            targetModule.classList.add('active');
        }

        state.currentModule = module;

        // Scroll to top of main content
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.scrollTo({ top: 0, behavior: 'smooth' });
        }

        // Re-draw connections if returning to home
        if (module === 'home') {
            setTimeout(initMindmapConnections, 100);
        }
    }

    function handlePillarClick(e) {
        const pillar = e.currentTarget.dataset.pillar;
        const moduleMap = {
            'monitoring': 'monitoring',
            'stack': 'ebs',
            'apm': 'apm',
            'logs': 'loganalytics',
            'opsinsights': 'opsinsights',
            'dbmgmt': 'dbmgmt',
            'sevenkingdoms': 'sevenkingdoms'
        };

        const targetModule = moduleMap[pillar];
        if (targetModule && targetModule !== state.currentModule) {
            const navItem = document.querySelector(`.nav-item[data-module="${targetModule}"]`);
            if (navItem) navItem.click();
        }
    }

    // ============================================
    // Use Case Handlers
    // ============================================
    function handleUseCaseClick(e) {
        const tab = e.currentTarget;
        const usecase = tab.dataset.usecase;

        if (usecase === state.currentUseCase) return;

        // Update tabs
        elements.useCaseTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');

        // Update content
        elements.useCaseContents.forEach(content => content.classList.remove('active'));
        const targetContent = document.getElementById(`usecase-${usecase}`);
        if (targetContent) {
            targetContent.classList.add('active');
        }

        state.currentUseCase = usecase;
    }

    // ============================================
    // Cloud Guard Toggle
    // ============================================
    function handleCloudGuardToggle(e) {
        const option = e.currentTarget;
        const value = option.dataset.value;

        if (value === state.cloudGuardMode) return;

        // Update toggle state
        const options = elements.cloudGuardToggle.querySelectorAll('.toggle-option');
        options.forEach(opt => opt.classList.remove('active'));
        option.classList.add('active');

        // Update slider position
        elements.cloudGuardToggle.dataset.value = value;

        // Update security halo
        if (elements.securityHalo) {
            if (value === 'paid') {
                elements.securityHalo.classList.add('paid');
            } else {
                elements.securityHalo.classList.remove('paid');
            }
        }

        state.cloudGuardMode = value;

        // Update badge text
        const badge = document.getElementById('cloudGuardBadge');
        if (badge) {
            badge.querySelector('span').textContent = value === 'paid' ? 'Cloud Guard Paid' : 'Cloud Guard';
        }
    }

    // ============================================
    // Mindmap Connections
    // ============================================
    function initMindmapConnections() {
        if (!elements.connectionLines || !elements.mindmap) return;

        const svg = elements.connectionLines;
        const mindmapRect = elements.mindmap.getBoundingClientRect();

        // Clear existing lines
        svg.innerHTML = '';

        // Set SVG dimensions
        svg.setAttribute('width', mindmapRect.width);
        svg.setAttribute('height', mindmapRect.height);

        // Get central node position
        const centralNode = document.getElementById('centralNode');
        if (!centralNode) return;

        const centralRect = centralNode.getBoundingClientRect();
        const centerX = centralRect.left + centralRect.width / 2 - mindmapRect.left;
        const centerY = centralRect.top + centralRect.height / 2 - mindmapRect.top;

        // Draw lines to pillar nodes
        document.querySelectorAll('.pillar-node').forEach(pillar => {
            const pillarRect = pillar.getBoundingClientRect();
            const pillarX = pillarRect.left + pillarRect.width / 2 - mindmapRect.left;
            const pillarY = pillarRect.top + pillarRect.height / 2 - mindmapRect.top;

            const line = createConnectionLine(centerX, centerY, pillarX, pillarY);
            svg.appendChild(line);
        });

        // Add gradient definition
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const gradient = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
        gradient.id = 'lineGradient';
        gradient.innerHTML = `
            <stop offset="0%" style="stop-color:rgba(199, 70, 52, 0.6)"/>
            <stop offset="100%" style="stop-color:rgba(199, 70, 52, 0.1)"/>
        `;
        defs.appendChild(gradient);
        svg.insertBefore(defs, svg.firstChild);
    }

    function createConnectionLine(x1, y1, x2, y2) {
        // Create a subtle curved path instead of a straight dashed line
        const dx = x2 - x1;
        const dy = y2 - y1;
        const len = Math.sqrt(dx * dx + dy * dy);

        if (len === 0) return document.createElementNS('http://www.w3.org/2000/svg', 'path');

        // Perpendicular offset for curve control point
        const curvature = len * 0.08;
        const nx = -dy / len;
        const ny = dx / len;

        const mx = (x1 + x2) / 2 + nx * curvature;
        const my = (y1 + y2) / 2 + ny * curvature;

        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`);
        path.setAttribute('stroke', 'url(#lineGradient)');
        path.setAttribute('stroke-width', '1.5');
        path.setAttribute('fill', 'none');
        path.style.opacity = '0.4';
        return path;
    }

    // ============================================
    // Interactive Elements
    // ============================================
    function handleClusterClick(e) {
        const bubble = e.currentTarget;
        const label = bubble.querySelector('.cluster-label').textContent;

        // Update cluster detail panel
        const detailPanel = document.querySelector('.cluster-detail-panel');
        if (detailPanel) {
            const count = bubble.querySelector('.cluster-count').textContent;
            detailPanel.querySelector('h4').textContent = `Cluster: ${label} (${count} records)`;
        }

        // Visual feedback
        document.querySelectorAll('.cluster-bubble').forEach(b => {
            b.style.opacity = b === bubble ? '1' : '0.5';
        });

        setTimeout(() => {
            document.querySelectorAll('.cluster-bubble').forEach(b => {
                b.style.opacity = '1';
            });
        }, 2000);
    }

    function handleBrazilClick() {
        const regionDetail = document.getElementById('regionDetail');
        if (regionDetail) {
            regionDetail.scrollIntoView({ behavior: 'smooth', block: 'center' });
            regionDetail.classList.add('highlight');
            setTimeout(() => regionDetail.classList.remove('highlight'), 2000);
        }
    }

    function handleStuckJobClick() {
        const detailPanel = document.getElementById('jobDetailPanel');
        if (detailPanel) {
            detailPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
            detailPanel.style.animation = 'none';
            detailPanel.offsetHeight; // Trigger reflow
            detailPanel.style.animation = 'pulseHighlight 0.5s ease-out';
        }
    }

    function handleSuggestionClick(e) {
        const text = e.currentTarget.textContent;
        const queryInput = document.querySelector('.query-input');
        if (queryInput) {
            queryInput.value = text;
            queryInput.focus();
        }
    }

    function handlePromptClick(e) {
        const text = e.currentTarget.textContent;
        const chatInput = document.querySelector('.chat-input');
        if (chatInput) {
            chatInput.value = text;
            chatInput.focus();
        }
    }

    function handleViewToggle(e) {
        const btn = e.currentTarget;
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
    }

    // ============================================
    // Animations
    // ============================================
    function initAnimations() {
        // Scroll-driven reveal animations for cards and sections
        const revealObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('revealed');
                    revealObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

        document.querySelectorAll(
            '.service-card, .stat-card, .step-item, .pillar-card, .example-card, ' +
            '.mcp-server-card, .namespace-card, .section-header, .resources-card, ' +
            '.tier-comparison-section, .certification-container'
        ).forEach(el => {
            el.classList.add('reveal-on-scroll');
            revealObserver.observe(el);
        });

        // Animate stat counters on scroll
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    animateCounter(entry.target);
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });

        document.querySelectorAll('.stat-value').forEach(stat => {
            observer.observe(stat);
        });
    }

    function initCounters() {
        // Initialize any dynamic counters
        updateLiveStats();
        setInterval(updateLiveStats, 5000);
    }

    function updateLiveStats() {
        // Simulate live updates
        const statValues = document.querySelectorAll('.stat-value');
        statValues.forEach(stat => {
            const currentText = stat.textContent;
            // Only update numeric values
            if (/^[\d.]+/.test(currentText)) {
                const num = parseFloat(currentText);
                const variance = (Math.random() - 0.5) * 0.1; // ±5% variance
                const newNum = num * (1 + variance);

                if (currentText.includes('M')) {
                    stat.textContent = newNum.toFixed(1) + 'M';
                } else if (currentText.includes('GB')) {
                    stat.textContent = Math.round(newNum) + ' GB';
                } else if (currentText.includes('ms')) {
                    stat.textContent = Math.round(newNum) + 'ms';
                } else if (currentText.includes('%')) {
                    stat.textContent = Math.min(100, newNum).toFixed(1) + '%';
                }
            }
        });
    }

    function animateCounter(element) {
        const text = element.textContent;
        const match = text.match(/^([\d.]+)(.*)$/);
        if (!match) return;

        const targetValue = parseFloat(match[1]);
        const suffix = match[2];
        const duration = 1500;
        const startTime = performance.now();
        const startValue = 0;

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);

            // Easing function
            const easeOutQuart = 1 - Math.pow(1 - progress, 4);
            const currentValue = startValue + (targetValue - startValue) * easeOutQuart;

            if (targetValue >= 100) {
                element.textContent = Math.round(currentValue) + suffix;
            } else {
                element.textContent = currentValue.toFixed(1) + suffix;
            }

            if (progress < 1) {
                requestAnimationFrame(update);
            }
        }

        requestAnimationFrame(update);
    }

    // ============================================
    // Data Flow Animation Enhancement
    // ============================================
    function initDataFlowAnimations() {
        // Create additional particles for data flow visualization
        document.querySelectorAll('.data-flow').forEach(flow => {
            for (let i = 0; i < 3; i++) {
                const particle = document.createElement('div');
                particle.className = 'flow-particle';
                particle.style.animationDelay = `${i * 0.5}s`;
                flow.appendChild(particle);
            }
        });
    }

    // ============================================
    // Sankey Diagram Interactivity
    // ============================================
    function initSankeyInteractions() {
        const sankeyNodes = document.querySelectorAll('.sankey-node');
        sankeyNodes.forEach(node => {
            node.addEventListener('mouseenter', () => {
                // Highlight connected flows
                const nodeType = node.classList.contains('source') ? 'source' :
                                 node.classList.contains('middleware') ? 'middleware' : 'destination';
                highlightFlows(nodeType);
            });

            node.addEventListener('mouseleave', () => {
                resetFlowHighlights();
            });
        });
    }

    function highlightFlows(nodeType) {
        const flows = document.querySelectorAll('.sankey-flow');
        flows.forEach((flow, index) => {
            if ((nodeType === 'source' && index === 0) ||
                (nodeType === 'middleware') ||
                (nodeType === 'destination' && index === 1)) {
                flow.style.opacity = '1';
            } else {
                flow.style.opacity = '0.3';
            }
        });
    }

    function resetFlowHighlights() {
        document.querySelectorAll('.sankey-flow').forEach(flow => {
            flow.style.opacity = '1';
        });
    }

    // ============================================
    // Trace Waterfall Interactivity
    // ============================================
    function initWaterfallInteractions() {
        const waterfallRows = document.querySelectorAll('.waterfall-row');
        waterfallRows.forEach(row => {
            row.addEventListener('click', () => {
                const serviceName = row.querySelector('.service-name').textContent.trim();
                showTraceDetail(serviceName);
            });
        });
    }

    function showTraceDetail(serviceName) {
        // Could expand to show more details about the trace span
        /* Trace detail view placeholder */
    }

    // ============================================
    // World Map Interactions
    // ============================================
    function initMapInteractions() {
        const markers = document.querySelectorAll('.session-marker');
        const regionDetail = document.getElementById('regionDetail');

        markers.forEach(marker => {
            marker.addEventListener('click', () => {
                const title = marker.querySelector('title')?.textContent || '';
                if (regionDetail) {
                    updateRegionDetail(title);
                }
            });
        });
    }

    function updateRegionDetail(info) {
        // Parse and display region info
        const parts = info.split(':');
        if (parts.length >= 2) {
            const region = parts[0].trim();
            const regionDetail = document.getElementById('regionDetail');
            if (regionDetail) {
                regionDetail.querySelector('h4').textContent = `${region} - Performance Analysis`;
            }
        }
    }

    // ============================================
    // Chat Interface Simulation
    // ============================================
    function initChatInterface() {
        const chatInput = document.querySelector('.chat-input');
        const chatSend = document.querySelector('.chat-send');
        const chatWindow = document.getElementById('chatWindow');

        if (chatSend && chatInput) {
            chatSend.addEventListener('click', () => {
                const message = chatInput.value.trim();
                if (message) {
                    addUserMessage(message);
                    chatInput.value = '';
                    simulateAIResponse(message);
                }
            });

            chatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    chatSend.click();
                }
            });
        }
    }

    function addUserMessage(text) {
        const chatWindow = document.getElementById('chatWindow');
        if (!chatWindow) return;

        const messageDiv = document.createElement('div');
        messageDiv.className = 'chat-message user';
        messageDiv.innerHTML = `
            <div class="message-content">
                <p>${escapeHtml(text)}</p>
            </div>
        `;
        chatWindow.appendChild(messageDiv);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    function simulateAIResponse(query) {
        const chatWindow = document.getElementById('chatWindow');
        if (!chatWindow) return;

        // Show typing indicator
        const typingDiv = document.createElement('div');
        typingDiv.className = 'chat-message assistant typing-indicator';
        typingDiv.innerHTML = `
            <div class="message-avatar">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                </svg>
            </div>
            <div class="message-content">
                <div class="typing-dots"><span></span><span></span><span></span></div>
            </div>
        `;
        chatWindow.appendChild(typingDiv);
        chatWindow.scrollTop = chatWindow.scrollHeight;

        // Replace typing indicator with actual response
        setTimeout(() => {
            typingDiv.remove();
            const response = generateAIResponse(query);
            const messageDiv = document.createElement('div');
            messageDiv.className = 'chat-message assistant';
            messageDiv.innerHTML = `
                <div class="message-avatar">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h1a7 7 0 0 1 7-7h1V5.73c-.6-.34-1-.99-1-1.73a2 2 0 0 1 2-2z"/>
                    </svg>
                </div>
                <div class="message-content">
                    <p>${response}</p>
                </div>
            `;
            chatWindow.appendChild(messageDiv);
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }, 1500);
    }

    function generateAIResponse(query) {
        const lowerQuery = query.toLowerCase();

        if (lowerQuery.includes('error') || lowerQuery.includes('trend')) {
            return 'I analyzed error trends across your infrastructure. Over the past week, there was a 23% increase in errors, primarily originating from the payment-service cluster. The spike correlates with deployment #1247 on Tuesday. I recommend reviewing the recent changes to the transaction timeout settings.';
        }

        if (lowerQuery.includes('cpu') || lowerQuery.includes('performance')) {
            return 'CPU usage comparison across regions shows: <strong>US-East</strong> averaging 45%, <strong>EU-West</strong> at 62%, and <strong>Asia-Pacific</strong> at 78%. The elevated usage in APAC appears related to a misconfigured auto-scaling policy. I can help you adjust the scaling thresholds.';
        }

        if (lowerQuery.includes('incident') || lowerQuery.includes('similar')) {
            return 'I found 3 similar incidents in the past 90 days. All involved the same pattern: database connection pool exhaustion during peak hours. The recommended fix from previous resolutions was increasing the max pool size from 50 to 100 connections.';
        }

        if (lowerQuery.includes('report')) {
            return 'I\'ve generated a draft incident report summarizing: <strong>Timeline</strong>, <strong>Impact Assessment</strong>, <strong>Root Cause Analysis</strong>, and <strong>Remediation Steps</strong>. The report includes data from Log Analytics, APM traces, and infrastructure metrics. Would you like me to export it as a PDF?';
        }

        if (lowerQuery.includes('log') || lowerQuery.includes('logan')) {
            return 'I queried Log Analytics using ML clustering. Found <strong>4 distinct clusters</strong> in the last 24 hours: (1) Authentication failures - 2,341 events from <code>auth-service</code>, (2) Timeout errors - 847 from <code>api-gateway</code>, (3) DB connection resets - 156 from <code>order-service</code>, (4) Healthy baseline - 458K events. Cluster #1 shows a brute-force pattern. Shall I create a Cloud Guard responder rule?';
        }

        if (lowerQuery.includes('database') || lowerQuery.includes('db') || lowerQuery.includes('sql') || lowerQuery.includes('awr')) {
            return 'AWR analysis for the last 1 hour shows: <strong>Top Wait Event:</strong> <code>db file sequential read</code> (42% of DB time). Top SQL by elapsed time: <code>SELECT * FROM orders o JOIN customers c ON o.cust_id=c.id WHERE o.status=:1</code> - missing index on <code>orders.status</code>. Buffer cache hit ratio: 89% (target: >95%). <strong>Recommendation:</strong> Create index <code>CREATE INDEX idx_orders_status ON orders(status)</code> and increase <code>SGA_TARGET</code>.';
        }

        if (lowerQuery.includes('memory') || lowerQuery.includes('oom') || lowerQuery.includes('leak')) {
            return 'Memory analysis across your fleet: 3 hosts are approaching critical thresholds. <strong>Host prod-api-03</strong>: 94% memory usage (RSS growing 50MB/day - possible leak in Java heap). <strong>Host prod-worker-07</strong>: 91% (OOM killer triggered twice this week). Ops Insights forecasts prod-api-03 will hit OOM in ~3 days at current growth rate. Recommend enabling heap dump on OOM and reviewing the connection pool configuration.';
        }

        if (lowerQuery.includes('latency') || lowerQuery.includes('slow') || lowerQuery.includes('timeout')) {
            return 'APM distributed trace analysis reveals the latency bottleneck: <strong>P99 latency</strong> spiked to 4.2s (baseline: 800ms) starting at 14:00 UTC. Trace breakdown: <code>frontend</code> → <code>api-gateway</code> (12ms) → <code>order-service</code> (45ms) → <code>inventory-db</code> (<strong>3.8s</strong>). The inventory database is the root cause - running a long-running batch job that\'s competing for I/O. Consider scheduling batch jobs during off-peak hours.';
        }

        if (lowerQuery.includes('alarm') || lowerQuery.includes('alert') || lowerQuery.includes('notification')) {
            return 'Current alarm status: <strong>3 Critical</strong>, <strong>7 Warning</strong>, <strong>142 OK</strong>. Critical alarms: (1) <code>prod-db-01 CPU > 95%</code> for 15 min, (2) <code>api-gateway error rate > 5%</code>, (3) <code>disk usage > 90%</code> on <code>prod-logs-02</code>. The disk alarm is recurring - Log Analytics archive job hasn\'t run since Monday. Shall I trigger the archive job via OCI Functions?';
        }

        if (lowerQuery.includes('cost') || lowerQuery.includes('budget') || lowerQuery.includes('spending')) {
            return 'Observability cost analysis for this month: <strong>Total: $2,847</strong> (within $3,500 budget). Breakdown: Log Analytics storage $1,240 (43%), APM traces $680 (24%), Custom Metrics $520 (18%), DB Management $407 (14%). <strong>Optimization opportunity:</strong> Moving 60-day-old logs to archive storage could save ~$380/month. 3 unused APM domains detected - decommissioning could save $120/month.';
        }

        if (lowerQuery.includes('security') || lowerQuery.includes('threat') || lowerQuery.includes('breach')) {
            return 'Security posture summary from Cloud Guard: <strong>Security Score: 82/100</strong>. <strong>5 Critical findings:</strong> (1) Public bucket detected in Production compartment, (2) Instance with unrestricted SSH access (0.0.0.0/0), (3) Unencrypted block volumes (2 instances), (4) IAM user without MFA, (5) Outdated OS image (CVE-2024-3094). Responder recipes are ready for auto-remediation on findings #1 and #2. Shall I activate them?';
        }

        return 'I\'m analyzing your query across multiple data sources including Log Analytics, APM, Monitoring, and Database Management. Based on the available data, I can provide insights about performance trends, error patterns, capacity planning, security posture, or cost optimization. Try asking about specific areas like "Show error trends", "Analyze database performance", or "Check alarm status".';
    }

    // ============================================
    // Utility Functions
    // ============================================
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ============================================
    // Keyboard Navigation
    // ============================================
    function initKeyboardNav() {
        document.addEventListener('keydown', (e) => {
            // Arrow keys to navigate modules
            if (e.altKey) {
                const moduleOrder = ['home', 'monitoring', 'ebs', 'fusion', 'loganalytics', 'apm', 'opsinsights', 'dbmgmt', 'ai', 'sevenkingdoms'];
                const currentIndex = moduleOrder.indexOf(state.currentModule);

                if (e.key === 'ArrowRight' && currentIndex < moduleOrder.length - 1) {
                    const nextModule = moduleOrder[currentIndex + 1];
                    document.querySelector(`.nav-item[data-module="${nextModule}"]`)?.click();
                } else if (e.key === 'ArrowLeft' && currentIndex > 0) {
                    const prevModule = moduleOrder[currentIndex - 1];
                    document.querySelector(`.nav-item[data-module="${prevModule}"]`)?.click();
                }
            }
        });
    }

    // ============================================
    // CSS Animation Injection
    // ============================================
    function injectAnimationStyles() {
        const style = document.createElement('style');
        style.textContent = `
            @keyframes pulseHighlight {
                0% { box-shadow: 0 0 0 0 rgba(199, 70, 52, 0.4); }
                70% { box-shadow: 0 0 0 20px rgba(199, 70, 52, 0); }
                100% { box-shadow: 0 0 0 0 rgba(199, 70, 52, 0); }
            }

            .highlight {
                animation: pulseHighlight 0.8s ease-out;
            }

            .cluster-bubble {
                transition: transform 0.3s ease, opacity 0.3s ease;
            }

            .sankey-flow {
                transition: opacity 0.3s ease;
            }
        `;
        document.head.appendChild(style);
    }

    // ============================================
    // Pillar Cards Drag and Drop
    // ============================================
    function initPillarDragDrop() {
        const pillarsGrid = document.getElementById('pillarsGrid');
        if (!pillarsGrid) {
            return;
            return;
        }

        let draggedCard = null;

        // Use event delegation on the grid container
        pillarsGrid.addEventListener('dragstart', (e) => {
            const card = e.target.closest('.pillar-card');
            if (!card) return;

            draggedCard = card;
            card.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            e.dataTransfer.setData('text/plain', card.dataset.pillarId || '');

            // Use setTimeout to allow the drag image to be captured
            setTimeout(() => {
                card.style.opacity = '0.4';
            }, 0);
        });

        pillarsGrid.addEventListener('dragend', (e) => {
            const card = e.target.closest('.pillar-card');
            if (!card) return;

            card.classList.remove('dragging');
            card.style.opacity = '';
            draggedCard = null;

            // Remove drag-over from all cards
            pillarsGrid.querySelectorAll('.pillar-card').forEach(c => {
                c.classList.remove('drag-over');
            });
        });

        pillarsGrid.addEventListener('dragover', (e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';

            const card = e.target.closest('.pillar-card');
            if (card && card !== draggedCard) {
                // Remove drag-over from all, then add to current
                pillarsGrid.querySelectorAll('.pillar-card').forEach(c => {
                    c.classList.remove('drag-over');
                });
                card.classList.add('drag-over');
            }
        });

        pillarsGrid.addEventListener('dragleave', (e) => {
            const card = e.target.closest('.pillar-card');
            if (card) {
                card.classList.remove('drag-over');
            }
        });

        pillarsGrid.addEventListener('drop', (e) => {
            e.preventDefault();

            const targetCard = e.target.closest('.pillar-card');
            if (!targetCard || !draggedCard || targetCard === draggedCard) return;

            targetCard.classList.remove('drag-over');

            const allCards = [...pillarsGrid.querySelectorAll('.pillar-card')];
            const draggedIndex = allCards.indexOf(draggedCard);
            const targetIndex = allCards.indexOf(targetCard);

            if (draggedIndex < targetIndex) {
                targetCard.parentNode.insertBefore(draggedCard, targetCard.nextSibling);
            } else {
                targetCard.parentNode.insertBefore(draggedCard, targetCard);
            }

            // Save order to localStorage
            savePillarOrder();

            // Visual feedback
            draggedCard.style.animation = 'none';
            draggedCard.offsetHeight; // Trigger reflow
            draggedCard.style.animation = 'dropBounce 0.3s ease-out';
        });

        // Load saved order on init
        loadPillarOrder();
    }

    function savePillarOrder() {
        const pillarsGrid = document.getElementById('pillarsGrid');
        if (!pillarsGrid) return;

        const order = [...pillarsGrid.querySelectorAll('.pillar-card')]
            .map(card => card.dataset.pillarId);
        localStorage.setItem('pillar-order', JSON.stringify(order));
    }

    function loadPillarOrder() {
        const pillarsGrid = document.getElementById('pillarsGrid');
        if (!pillarsGrid) return;

        const savedOrder = localStorage.getItem('pillar-order');
        if (!savedOrder) return;

        try {
            const order = JSON.parse(savedOrder);
            const cards = pillarsGrid.querySelectorAll('.pillar-card');
            const cardMap = new Map();

            cards.forEach(card => {
                cardMap.set(card.dataset.pillarId, card);
            });

            order.forEach(id => {
                const card = cardMap.get(id);
                if (card) {
                    pillarsGrid.appendChild(card);
                }
            });
        } catch (e) {
            console.warn('Could not load pillar order:', e);
        }
    }

    // ============================================
    // Mindmap Node Dragging
    // ============================================
    function initMindmapDrag() {
        const mindmapContainer = document.getElementById('mindmapContainer');
        const mindmap = document.getElementById('mindmap');
        if (!mindmapContainer || !mindmap) return;

        let activeNode = null;
        let startX = 0;
        let startY = 0;
        let initialX = 0;
        let initialY = 0;

        // Get all draggable nodes
        const draggableNodes = mindmap.querySelectorAll('.draggable-node');

        draggableNodes.forEach(node => {
            // Store initial position
            const rect = node.getBoundingClientRect();
            const containerRect = mindmap.getBoundingClientRect();
            node.dataset.initialX = rect.left - containerRect.left;
            node.dataset.initialY = rect.top - containerRect.top;

            // Mouse down event
            node.addEventListener('mousedown', (e) => {
                // Don't drag if clicking on EOL badge link
                if (e.target.closest('.eol-badge')) return;

                e.preventDefault();
                activeNode = node;
                startX = e.clientX;
                startY = e.clientY;

                // Get current transform or position
                const style = window.getComputedStyle(node);
                const transform = style.transform;

                if (transform && transform !== 'none') {
                    const matrix = new DOMMatrix(transform);
                    initialX = matrix.m41;
                    initialY = matrix.m42;
                } else {
                    initialX = 0;
                    initialY = 0;
                }

                node.classList.add('dragging');
                document.body.style.cursor = 'grabbing';
            });
        });

        // Mouse move - track on document for smooth dragging
        document.addEventListener('mousemove', (e) => {
            if (!activeNode) return;

            e.preventDefault();
            const deltaX = e.clientX - startX;
            const deltaY = e.clientY - startY;

            // Update position
            const newX = initialX + deltaX;
            const newY = initialY + deltaY;

            // For pillar nodes, adjust the transform
            if (activeNode.classList.contains('pillar-node')) {
                const pillar = activeNode.dataset.pillar;
                const baseTransforms = {
                    'monitoring': { x: 280, y: 0 },
                    'stack': { x: 140, y: -242 },
                    'apm': { x: -140, y: -242 },
                    'logs': { x: -280, y: 0 },
                    'opsinsights': { x: -140, y: 242 },
                    'dbmgmt': { x: 140, y: 242 }
                };
                const base = baseTransforms[pillar] || { x: 0, y: 0 };
                activeNode.style.transform = `translate(calc(-50% + ${base.x + deltaX}px), calc(-50% + ${base.y + deltaY}px))`;
            } else {
                // For other nodes (enablers, services)
                activeNode.style.transform = `translate(${newX}px, ${newY}px)`;
            }

            // Redraw connections
            initMindmapConnections();
        });

        // Mouse up - finish dragging
        document.addEventListener('mouseup', () => {
            if (!activeNode) return;

            activeNode.classList.remove('dragging');
            document.body.style.cursor = '';

            // Save position to localStorage
            saveMindmapPositions();

            activeNode = null;
        });

        // Reset button
        const resetBtn = document.getElementById('resetPositions');
        if (resetBtn) {
            resetBtn.addEventListener('click', resetMindmapPositions);
        }

        // Load saved positions
        loadMindmapPositions();

    }

    function saveMindmapPositions() {
        const mindmap = document.getElementById('mindmap');
        if (!mindmap) return;

        const positions = {};
        const draggableNodes = mindmap.querySelectorAll('.draggable-node');

        draggableNodes.forEach(node => {
            const id = node.dataset.pillar || node.dataset.enabler || node.dataset.service;
            if (id) {
                positions[id] = node.style.transform;
            }
        });

        localStorage.setItem('mindmap-positions', JSON.stringify(positions));
        localStorage.setItem('mindmap-layout-version', 'v2');
    }

    function loadMindmapPositions() {
        const mindmap = document.getElementById('mindmap');
        if (!mindmap) return;

        // Clear stale positions from previous layout version
        const layoutVersion = 'v2';
        if (localStorage.getItem('mindmap-layout-version') !== layoutVersion) {
            localStorage.removeItem('mindmap-positions');
            localStorage.setItem('mindmap-layout-version', layoutVersion);
            return;
        }

        const saved = localStorage.getItem('mindmap-positions');
        if (!saved) return;

        try {
            const positions = JSON.parse(saved);
            const draggableNodes = mindmap.querySelectorAll('.draggable-node');

            draggableNodes.forEach(node => {
                const id = node.dataset.pillar || node.dataset.enabler || node.dataset.service;
                if (id && positions[id]) {
                    node.style.transform = positions[id];
                }
            });

            // Redraw connections after loading positions
            setTimeout(initMindmapConnections, 100);
        } catch (e) {
            console.warn('Could not load mindmap positions:', e);
        }
    }

    function resetMindmapPositions() {
        const mindmap = document.getElementById('mindmap');
        if (!mindmap) return;

        // Clear saved positions
        localStorage.removeItem('mindmap-positions');

        // Reset pillar nodes to default transforms
        const pillarDefaults = {
            'monitoring': 'translate(calc(-50% + 280px), -50%)',
            'stack': 'translate(calc(-50% + 140px), calc(-50% - 242px))',
            'apm': 'translate(calc(-50% - 140px), calc(-50% - 242px))',
            'logs': 'translate(calc(-50% - 280px), -50%)',
            'opsinsights': 'translate(calc(-50% - 140px), calc(-50% + 242px))',
            'dbmgmt': 'translate(calc(-50% + 140px), calc(-50% + 242px))'
        };

        document.querySelectorAll('.pillar-node').forEach(node => {
            const pillar = node.dataset.pillar;
            if (pillar && pillarDefaults[pillar]) {
                node.style.transform = pillarDefaults[pillar];
            }
        });

        // Reset other draggable nodes
        document.querySelectorAll('.enabler-node, .oci-service-node').forEach(node => {
            node.style.transform = '';
        });

        // Redraw connections
        setTimeout(initMindmapConnections, 100);
    }

    // ============================================
    // Service Cards Interactivity
    // ============================================
    function initServiceCardEnhancements() {
        // Add hover effects and click tracking for service cards
        const serviceCards = document.querySelectorAll('.service-card');

        serviceCards.forEach(card => {
            card.addEventListener('mouseenter', () => {
                // Add subtle glow on hover
                const serviceName = card.querySelector('h3')?.textContent;
                if (serviceName) {
                }
            });
        });

        // EOL service card special handling
        const eolCards = document.querySelectorAll('.eol-service');
        eolCards.forEach(card => {
            card.addEventListener('click', (e) => {
                // If clicking the EOL link, don't prevent default
                if (e.target.closest('.eol-link')) {
                    return;
                }
            });
        });
    }

    // ============================================
    // Query Builder (Monitoring Module)
    // ============================================
    function initQueryBuilder() {
        // Metric names by namespace (sample data)
        const metricsByNamespace = {
            'oci_computeagent': ['CpuUtilization', 'MemoryUtilization', 'DiskBytesRead', 'DiskBytesWritten', 'NetworkBytesIn', 'NetworkBytesOut', 'LoadAverage'],
            'oci_compute_infrastructure_health': ['instance_status', 'health_status', 'maintenance_reboot'],
            'oci_autonomous_database': ['CpuUtilization', 'StorageUsed', 'SessionCount', 'ExecutionCount', 'RunningStatementCount', 'SQLStatements'],
            'oci_database': ['CpuUtilization', 'StorageUsedPercent', 'SessionsActive', 'ParseCount', 'ExecuteCount'],
            'oci_vcn': ['VnicFromNetworkBytes', 'VnicToNetworkBytes', 'VnicFromNetworkPackets', 'VnicToNetworkPackets'],
            'oci_lbaas': ['ActiveConnections', 'BytesReceived', 'BytesSent', 'FailedSSLClientCertVerify', 'FailedSSLHandshake'],
            'oci_objectstorage': ['ObjectCount', 'StoredBytes', 'GetRequests', 'PutRequests', 'DeleteRequests'],
            'oci_blockstore': ['VolumeReadOps', 'VolumeWriteOps', 'VolumeReadBytes', 'VolumeWriteBytes', 'VolumeReadThroughput'],
            'oci_streaming': ['PublishMessageCount', 'ConsumeMessageCount', 'PublishBytes', 'ConsumeBytes'],
            'oci_faas': ['FunctionInvocationCount', 'FunctionExecutionDuration', 'FunctionMemoryUtilization', 'FunctionResponseCount'],
            'oracle_apm_synthetics': ['availability', 'responseTime', 'dnsTime', 'connectTime', 'sslHandshakeTime'],
            'oracle_apm_rum': ['pageLoadTime', 'domContentLoaded', 'firstPaint', 'firstContentfulPaint', 'jsErrors']
        };

        // Initialize tag inputs
        initTagInput('compartmentsInput', 'compartmentSearch', 'selectedCompartments', 'compartmentDropdown');
        initTagInput('regionsInput', 'regionSearch', 'selectedRegions', 'regionDropdown', true);

        // Initialize namespace searchable select
        initNamespaceSelect();

        // Initialize add region button
        const addRegionBtn = document.getElementById('addRegionBtn');
        const regionSearchInput = document.getElementById('regionSearch');
        if (addRegionBtn && regionSearchInput) {
            addRegionBtn.addEventListener('click', () => {
                const value = regionSearchInput.value.trim();
                if (value) {
                    addTag('selectedRegions', value);
                    regionSearchInput.value = '';
                }
            });

            regionSearchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addRegionBtn.click();
                }
            });
        }

        function initTagInput(containerId, inputId, tagsContainerId, dropdownId, allowCustom = false) {
            const container = document.getElementById(containerId);
            const input = document.getElementById(inputId);
            const dropdown = document.getElementById(dropdownId);

            if (!container || !input || !dropdown) return;

            // Show dropdown on focus
            input.addEventListener('focus', () => {
                dropdown.classList.add('active');
            });

            // Filter dropdown on input
            input.addEventListener('input', () => {
                const filter = input.value.toLowerCase();
                const items = dropdown.querySelectorAll('.dropdown-item');
                items.forEach(item => {
                    const text = item.textContent.toLowerCase();
                    item.style.display = text.includes(filter) ? 'block' : 'none';
                });
            });

            // Select item from dropdown
            dropdown.addEventListener('click', (e) => {
                const item = e.target.closest('.dropdown-item');
                if (item && !item.classList.contains('disabled')) {
                    const value = item.dataset.value;
                    if (value) {
                        addTag(tagsContainerId, value);
                        input.value = '';
                        dropdown.classList.remove('active');
                    }
                }
            });

            // Close dropdown on outside click
            document.addEventListener('click', (e) => {
                if (!container.contains(e.target)) {
                    dropdown.classList.remove('active');
                }
            });

            // Remove tag handler
            container.addEventListener('click', (e) => {
                if (e.target.classList.contains('tag-remove')) {
                    e.target.closest('.tag').remove();
                }
            });
        }

        function addTag(containerId, value) {
            const container = document.getElementById(containerId);
            if (!container) return;

            // Check if already exists
            const existing = container.querySelector(`[data-value="${value}"]`);
            if (existing) return;

            const tag = document.createElement('span');
            tag.className = 'tag';
            tag.innerHTML = `${value} <button class="tag-remove" data-value="${value}">&times;</button>`;
            container.appendChild(tag);
        }

        function initNamespaceSelect() {
            const input = document.getElementById('namespaceSearch');
            const dropdown = document.getElementById('namespaceDropdown');
            const metricInput = document.getElementById('metricNameSearch');
            const metricDropdown = document.getElementById('metricNameDropdown');

            if (!input || !dropdown) return;

            let selectedNamespace = '';

            // Show dropdown on focus
            input.addEventListener('focus', () => {
                dropdown.classList.add('active');
            });

            // Filter dropdown on input
            input.addEventListener('input', () => {
                const filter = input.value.toLowerCase();
                const items = dropdown.querySelectorAll('.dropdown-item:not(.add-custom)');
                let hasMatch = false;

                items.forEach(item => {
                    const text = item.textContent.toLowerCase();
                    const value = item.dataset.value?.toLowerCase() || '';
                    const show = text.includes(filter) || value.includes(filter);
                    item.style.display = show ? 'block' : 'none';
                    if (show && item.dataset.value) hasMatch = true;
                });

                // Show sections based on child visibility
                dropdown.querySelectorAll('.dropdown-section').forEach(section => {
                    let nextItem = section.nextElementSibling;
                    let hasVisibleChild = false;
                    while (nextItem && !nextItem.classList.contains('dropdown-section')) {
                        if (nextItem.style.display !== 'none' && nextItem.classList.contains('dropdown-item')) {
                            hasVisibleChild = true;
                        }
                        nextItem = nextItem.nextElementSibling;
                    }
                    section.style.display = hasVisibleChild ? 'block' : 'none';
                });
            });

            // Select namespace
            dropdown.addEventListener('click', (e) => {
                const item = e.target.closest('.dropdown-item');
                if (!item) return;

                if (item.classList.contains('add-custom')) {
                    // Prompt for custom namespace
                    const customNs = prompt('Enter custom namespace:');
                    if (customNs && customNs.trim()) {
                        selectNamespace(customNs.trim());
                    }
                } else if (item.dataset.value) {
                    selectNamespace(item.dataset.value);
                }
                dropdown.classList.remove('active');
            });

            // Close dropdown on outside click
            document.addEventListener('click', (e) => {
                if (!input.closest('.searchable-select').contains(e.target)) {
                    dropdown.classList.remove('active');
                }
            });

            // Allow typing custom namespace and pressing Enter
            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    const value = input.value.trim();
                    if (value) {
                        selectNamespace(value);
                        dropdown.classList.remove('active');
                    }
                }
            });

            function selectNamespace(namespace) {
                selectedNamespace = namespace;
                input.value = namespace;

                // Mark as selected in dropdown
                dropdown.querySelectorAll('.dropdown-item').forEach(item => {
                    item.classList.toggle('selected', item.dataset.value === namespace);
                });

                // Enable and populate metric names
                if (metricInput && metricDropdown) {
                    metricInput.disabled = false;
                    metricInput.placeholder = 'Search metrics...';

                    // Get metrics for this namespace
                    const metrics = metricsByNamespace[namespace] || [];

                    metricDropdown.innerHTML = '';
                    if (metrics.length === 0) {
                        metricDropdown.innerHTML = '<div class="dropdown-item disabled">No metrics found for this namespace</div>';
                        metricDropdown.innerHTML += '<div class="dropdown-item add-custom"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add custom metric...</div>';
                    } else {
                        metrics.forEach(metric => {
                            const item = document.createElement('div');
                            item.className = 'dropdown-item';
                            item.dataset.value = metric;
                            item.textContent = metric;
                            metricDropdown.appendChild(item);
                        });
                        const addCustom = document.createElement('div');
                        addCustom.className = 'dropdown-item add-custom';
                        addCustom.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg> Add custom metric...';
                        metricDropdown.appendChild(addCustom);
                    }

                    // Initialize metric select behavior
                    initMetricSelect();
                }
            }

            function initMetricSelect() {
                if (!metricInput || !metricDropdown) return;

                metricInput.addEventListener('focus', () => {
                    metricDropdown.classList.add('active');
                });

                metricInput.addEventListener('input', () => {
                    const filter = metricInput.value.toLowerCase();
                    metricDropdown.querySelectorAll('.dropdown-item:not(.add-custom)').forEach(item => {
                        const text = item.textContent.toLowerCase();
                        item.style.display = text.includes(filter) ? 'block' : 'none';
                    });
                });

                metricDropdown.addEventListener('click', (e) => {
                    const item = e.target.closest('.dropdown-item');
                    if (!item) return;

                    if (item.classList.contains('add-custom')) {
                        const customMetric = prompt('Enter custom metric name:');
                        if (customMetric && customMetric.trim()) {
                            metricInput.value = customMetric.trim();
                        }
                    } else if (item.dataset.value) {
                        metricInput.value = item.dataset.value;
                    }
                    metricDropdown.classList.remove('active');
                });

                document.addEventListener('click', (e) => {
                    if (!metricInput.closest('.searchable-select').contains(e.target)) {
                        metricDropdown.classList.remove('active');
                    }
                });
            }
        }

        // Add Query button
        const addQueryBtn = document.getElementById('addQuery');
        if (addQueryBtn) {
            let queryCount = 1;
            addQueryBtn.addEventListener('click', () => {
                queryCount++;
                const queryContainer = document.querySelector('.query-builder-container');
                if (!queryContainer) return;

                const newCard = document.createElement('div');
                newCard.className = 'query-card';
                newCard.id = `queryCard${queryCount}`;
                newCard.innerHTML = `
                    <div class="query-header">
                        <span class="query-title">Query ${queryCount}</span>
                        <div class="query-actions">
                            <button class="btn-ghost remove-query" title="Remove query" style="padding: 4px 8px; font-size: 12px; color: var(--error);">Remove</button>
                        </div>
                    </div>
                    <div class="query-form">
                        <div class="query-row">
                            <div class="query-field">
                                <label class="field-label">METRIC NAMESPACE</label>
                                <div class="searchable-select">
                                    <input type="text" class="select-input" placeholder="Type namespace (e.g., oci_computeagent)...">
                                </div>
                            </div>
                            <div class="query-field">
                                <label class="field-label">METRIC NAME</label>
                                <div class="searchable-select">
                                    <input type="text" class="select-input" placeholder="Type metric name...">
                                </div>
                            </div>
                            <div class="query-field small">
                                <label class="field-label">INTERVAL</label>
                                <select class="query-select">
                                    <option value="1m">1 minute</option>
                                    <option value="5m">5 minutes</option>
                                    <option value="1h" selected>1 hour</option>
                                    <option value="1d">1 day</option>
                                </select>
                            </div>
                            <div class="query-field small">
                                <label class="field-label">STATISTIC</label>
                                <select class="query-select">
                                    <option value="mean" selected>Mean</option>
                                    <option value="sum">Sum</option>
                                    <option value="max">Max</option>
                                    <option value="min">Min</option>
                                    <option value="p99">P99</option>
                                </select>
                            </div>
                        </div>
                    </div>
                `;

                // Insert before the query actions/results
                const existingResults = document.getElementById('queryResults');
                if (existingResults) {
                    queryContainer.insertBefore(newCard, existingResults);
                } else {
                    queryContainer.appendChild(newCard);
                }

                // Bind remove button
                newCard.querySelector('.remove-query').addEventListener('click', () => {
                    newCard.remove();
                });
            });
        }

        // Run All Queries button
        const runAllBtn = document.getElementById('runAllQueries');
        if (runAllBtn) {
            runAllBtn.addEventListener('click', () => {
                const allCards = document.querySelectorAll('.query-card');
                const results = document.getElementById('queryResults');
                if (!results) return;

                const queries = [];
                allCards.forEach(card => {
                    const ns = card.querySelector('.select-input')?.value || 'N/A';
                    const metric = card.querySelectorAll('.select-input')[1]?.value || 'N/A';
                    if (ns && ns !== 'N/A') {
                        queries.push({ namespace: ns, metric: metric || 'all metrics' });
                    }
                });

                if (queries.length === 0) {
                    results.innerHTML = `
                        <div style="padding: 40px; text-align: center;">
                            <div style="font-size: 14px; color: var(--text-muted);">
                                Please configure at least one query with a namespace
                            </div>
                        </div>
                    `;
                    return;
                }

                let html = '<div style="padding: 24px;">';
                html += '<h4 style="color: var(--text-primary); margin-bottom: 16px;">Query Results</h4>';
                queries.forEach((q, i) => {
                    html += `
                        <div style="padding: 16px; background: var(--surface-2); border-radius: 8px; margin-bottom: 12px;">
                            <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 4px;">
                                Query ${i + 1}: <strong>${q.namespace}</strong> / <strong>${q.metric}</strong>
                            </div>
                            <div style="font-size: 12px; color: var(--text-muted);">(Demo - connect to OCI API for real data)</div>
                            <svg viewBox="0 0 200 60" style="width: 100%; max-width: 300px; height: 60px; margin-top: 8px;">
                                <polyline points="0,${40 + Math.random() * 15} 40,${20 + Math.random() * 20} 80,${30 + Math.random() * 15} 120,${15 + Math.random() * 20} 160,${25 + Math.random() * 15} 200,${10 + Math.random() * 20}"
                                    fill="none" stroke="var(--monitoring-color)" stroke-width="2"/>
                            </svg>
                        </div>
                    `;
                });
                html += '</div>';
                results.innerHTML = html;
            });
        }

        // Initialize dimension adding
        const addDimensionBtn = document.getElementById('addDimension1');
        const dimensionsList = document.getElementById('dimensionsList1');
        if (addDimensionBtn && dimensionsList) {
            addDimensionBtn.addEventListener('click', () => {
                const row = document.createElement('div');
                row.className = 'dimension-row';
                row.innerHTML = `
                    <input type="text" class="select-input" placeholder="Dimension name">
                    <input type="text" class="select-input" placeholder="Dimension value">
                    <button class="tag-remove" title="Remove dimension">&times;</button>
                `;
                row.querySelector('.tag-remove').addEventListener('click', () => row.remove());
                dimensionsList.appendChild(row);
            });
        }

        // Run query button (placeholder action)
        const runQueryBtn = document.getElementById('runQuery1');
        if (runQueryBtn) {
            runQueryBtn.addEventListener('click', () => {
                const namespace = document.getElementById('namespaceSearch')?.value;
                const metric = document.getElementById('metricNameSearch')?.value;

                if (!namespace) {
                    alert('Please select a namespace');
                    return;
                }
                if (!metric) {
                    alert('Please select a metric');
                    return;
                }

                // Show placeholder result
                const results = document.getElementById('queryResults');
                if (results) {
                    results.innerHTML = `
                        <div style="padding: 40px; text-align: center;">
                            <div style="font-size: 16px; color: var(--text-primary); margin-bottom: 8px;">
                                Query executed for <strong>${namespace}</strong> / <strong>${metric}</strong>
                            </div>
                            <div style="font-size: 13px; color: var(--text-muted);">
                                (This is a demo - connect to OCI API for real metrics data)
                            </div>
                            <div style="margin-top: 24px; padding: 20px; background: var(--surface-2); border-radius: 8px; display: inline-block;">
                                <svg viewBox="0 0 200 80" style="width: 200px; height: 80px;">
                                    <polyline points="0,60 30,50 60,55 90,30 120,40 150,20 180,35 200,25"
                                        fill="none" stroke="var(--monitoring-color)" stroke-width="2"/>
                                </svg>
                            </div>
                        </div>
                    `;
                }
            });
        }
    }

    // ============================================
    // Initialize Additional Features
    // ============================================
    function initAdditionalFeatures() {
        initDataFlowAnimations();
        initSankeyInteractions();
        initWaterfallInteractions();
        initMapInteractions();
        initChatInterface();
        initKeyboardNav();
        injectAnimationStyles();
        initPillarDragDrop();
        initMindmapDrag();
        initServiceCardEnhancements();
        initQueryBuilder();
    }

    // ============================================
    // Boot
    // ============================================
    document.addEventListener('DOMContentLoaded', () => {
        init();
        initAdditionalFeatures();
    });

})();
