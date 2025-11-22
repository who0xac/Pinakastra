// Pinakastra Dashboard JavaScript

class PinakastraApp {
    constructor() {
        this.ws = null;
        this.activeScans = new Map();
        this.init();
    }

    init() {
        this.setupWebSocket();
        this.setupNavigation();
        this.setupModal();
        this.loadInitialData();
    }

    // WebSocket Connection
    setupWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            this.updateConnectionStatus('connected');
            console.log('WebSocket connected');
        };

        this.ws.onclose = () => {
            this.updateConnectionStatus('disconnected');
            console.log('WebSocket disconnected');
            // Reconnect after 3 seconds
            setTimeout(() => this.setupWebSocket(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
        };
    }

    updateConnectionStatus(status) {
        const statusEl = document.getElementById('ws-status');
        statusEl.className = `status-indicator ${status}`;
        statusEl.querySelector('.text').textContent =
            status === 'connected' ? 'Connected' :
            status === 'disconnected' ? 'Disconnected' : 'Connecting...';
    }

    handleMessage(message) {
        console.log('Received:', message);

        switch (message.type) {
            case 'scan_start':
                this.onScanStart(message.data);
                break;
            case 'tool_start':
                this.onToolStart(message.data);
                break;
            case 'tool_complete':
                this.onToolComplete(message.data);
                break;
            case 'scan_complete':
                this.onScanComplete(message.data);
                break;
            case 'error':
                this.onError(message.data);
                break;
            case 'critical':
                this.onCritical(message.data);
                break;
        }
    }

    // Event Handlers
    onScanStart(data) {
        this.activeScans.set(data.domain, {
            domain: data.domain,
            startTime: new Date(),
            tools: {},
            status: 'running'
        });
        this.addActivity('🚀', `Scan started for ${data.domain}`, 'info');
        this.updateStats();
    }

    onToolStart(data) {
        const scan = this.activeScans.get(data.domain);
        if (scan) {
            scan.tools[data.tool] = { status: 'running', startTime: new Date() };
        }
        this.addActivity('🔄', `${data.tool} started on ${data.domain}`, 'info');
    }

    onToolComplete(data) {
        this.addActivity(
            data.success ? '✅' : '❌',
            `${data.tool} completed (${data.findings} findings)`,
            data.success ? 'success' : 'error'
        );
        this.updateStats();
    }

    onScanComplete(data) {
        this.activeScans.delete(data.domain);
        this.addActivity('🎯', `Scan completed for ${data.domain}`, 'success');
        this.updateStats();
        this.loadScans();
    }

    onError(data) {
        this.addActivity('❌', data.message, 'error');
    }

    onCritical(data) {
        this.addActivity('🚨', data.message, 'critical');
        // Show notification
        if (Notification.permission === 'granted') {
            new Notification('Pinakastra - Critical Finding', {
                body: data.message,
                icon: '/static/icon.png'
            });
        }
    }

    // UI Updates
    addActivity(icon, message, type) {
        const feed = document.getElementById('activity-feed');
        const empty = feed.querySelector('.activity-empty');
        if (empty) empty.remove();

        const item = document.createElement('div');
        item.className = `activity-item ${type}`;
        item.innerHTML = `
            <span class="activity-icon">${icon}</span>
            <div class="activity-content">
                <div class="activity-title">${message}</div>
                <div class="activity-time">${new Date().toLocaleTimeString()}</div>
            </div>
        `;

        feed.insertBefore(item, feed.firstChild);

        // Keep only last 50 items
        while (feed.children.length > 50) {
            feed.removeChild(feed.lastChild);
        }
    }

    updateStats() {
        document.getElementById('active-scans').textContent = this.activeScans.size;
    }

    // Navigation
    setupNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const page = item.dataset.page;
                this.navigateTo(page);
            });
        });
    }

    navigateTo(page) {
        // Update nav
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === page);
        });

        // Update pages
        document.querySelectorAll('.page').forEach(p => {
            p.classList.toggle('active', p.id === `page-${page}`);
        });

        // Load page data
        if (page === 'scans') this.loadScans();
        if (page === 'tools') this.loadTools();
    }

    // Modal
    setupModal() {
        const modal = document.getElementById('new-scan-modal');
        const openBtn = document.getElementById('new-scan-btn');
        const closeBtns = modal.querySelectorAll('.modal-close');

        openBtn.addEventListener('click', () => {
            modal.classList.add('active');
        });

        closeBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                modal.classList.remove('active');
            });
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    }

    // Data Loading
    async loadInitialData() {
        await this.loadScans();
        await this.loadTools();

        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    async loadScans() {
        try {
            const response = await fetch('/api/scans');
            const scans = await response.json();

            // Update stats
            document.getElementById('total-scans').textContent = scans?.length || 0;
            document.getElementById('completed-scans').textContent = scans?.length || 0;

            // Update recent scans
            const container = document.getElementById('recent-scans');
            if (!scans || scans.length === 0) {
                container.innerHTML = '<div class="activity-empty"><p>No scans yet. Start your first scan!</p></div>';
                return;
            }

            container.innerHTML = scans.slice(0, 5).map(scan => `
                <div class="scan-card" data-domain="${scan.domain}">
                    <div class="scan-info">
                        <div class="scan-domain">${scan.domain}</div>
                        <div class="scan-meta">
                            <span>📅 ${new Date(scan.timestamp).toLocaleDateString()}</span>
                            <span>🛠️ ${scan.tools} tools</span>
                        </div>
                    </div>
                    <span class="scan-status completed">Completed</span>
                </div>
            `).join('');

            // Update table
            const tbody = document.getElementById('scans-table-body');
            tbody.innerHTML = scans.map(scan => `
                <tr>
                    <td><strong>${scan.domain}</strong></td>
                    <td>${new Date(scan.timestamp).toLocaleString()}</td>
                    <td>${scan.tools}</td>
                    <td><span class="scan-status completed">Completed</span></td>
                    <td>
                        <button class="btn btn-secondary" onclick="app.viewScan('${scan.domain}')">View</button>
                    </td>
                </tr>
            `).join('');

        } catch (error) {
            console.error('Failed to load scans:', error);
        }
    }

    async loadTools() {
        try {
            const response = await fetch('/api/tools');
            const tools = await response.json();

            const container = document.getElementById('tools-grid');
            container.innerHTML = tools.map(tool => `
                <div class="tool-card">
                    <div class="tool-header">
                        <span class="tool-name">${tool.name}</span>
                        <span class="tool-badge installed">Installed</span>
                    </div>
                    <p class="tool-description">${tool.description}</p>
                    <div class="tool-phase">Phase ${tool.phase}</div>
                </div>
            `).join('');

            // Update tools selector in modal
            const selector = document.getElementById('tools-selector');
            selector.innerHTML = tools.map(tool => `
                <label class="tool-checkbox">
                    <input type="checkbox" name="tools" value="${tool.name}" checked>
                    ${tool.name}
                </label>
            `).join('');

        } catch (error) {
            console.error('Failed to load tools:', error);
        }
    }

    async viewScan(domain) {
        try {
            const response = await fetch(`/api/scan/${domain}`);
            const data = await response.json();
            console.log('Scan data:', data);
            // TODO: Show scan details modal
        } catch (error) {
            console.error('Failed to load scan:', error);
        }
    }
}

// Initialize app
const app = new PinakastraApp();
