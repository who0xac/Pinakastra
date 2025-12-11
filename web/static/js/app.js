// Pinakastra Dashboard Logic

function dashboard() {
    return {
        // State
        domain: window.location.hostname || 'target.com',
        theme: localStorage.getItem('theme') || 'dark',
        showExportMenu: false,
        activeTab: 'subdomains',
        autoScroll: true,

        // Data
        stats: {
            totalSubdomains: 0,
            liveHosts: 0,
            totalURLs: 0,
            totalVulnerabilities: 0,
            vulnsBySeverity: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0
            },
            httpStatusCodes: {},
            openPorts: 0
        },

        status: {
            phase: 'Initializing',
            phaseNumber: 0,
            progress: 0,
            message: 'Starting scan...',
            elapsedTime: '0m 0s'
        },

        subdomains: [],
        vulnerabilities: [],
        filteredVulnerabilities: [],
        liveFeed: [],
        openPorts: [],

        // Filters
        filters: {
            severity: '',
            type: '',
            search: ''
        },

        // WebSocket
        ws: null,
        vulnChart: null,

        // Initialize
        init() {
            this.applyTheme();
            this.connectWebSocket();
            this.initChart();
            this.loadInitialData();
            this.startTimer();
        },

        // Theme
        toggleTheme() {
            this.theme = this.theme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('theme', this.theme);
            this.applyTheme();
        },

        applyTheme() {
            document.documentElement.setAttribute('data-theme', this.theme);
        },

        // WebSocket Connection
        connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsURL = `${protocol}//${window.location.host}/ws`;

            this.ws = new WebSocket(wsURL);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.addToFeed('status', 'Connected to scanner');
            };

            this.ws.onmessage = (event) => {
                const update = JSON.parse(event.data);
                this.handleUpdate(update);
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.addToFeed('error', 'Connection error');
            };

            this.ws.onclose = () => {
                console.log('WebSocket closed, reconnecting...');
                setTimeout(() => this.connectWebSocket(), 5000);
            };
        },

        // Handle real-time updates
        handleUpdate(update) {
            switch (update.type) {
                case 'subdomain':
                    this.handleSubdomainUpdate(update.data);
                    break;
                case 'vulnerability':
                    this.handleVulnerabilityUpdate(update.data);
                    break;
                case 'status':
                    this.handleStatusUpdate(update.data);
                    break;
                case 'stats':
                    this.handleStatsUpdate(update.data);
                    break;
                case 'port':
                    this.handlePortUpdate(update.data);
                    break;
            }
        },

        handleSubdomainUpdate(data) {
            this.subdomains.push(data);
            this.stats.totalSubdomains = this.subdomains.length;
            this.addToFeed('subdomain', `🔍 Found subdomain: ${data.subdomain}`);

            if (data.status === 'active') {
                this.stats.liveHosts++;
            }
        },

        handleVulnerabilityUpdate(data) {
            this.vulnerabilities.push(data);
            this.stats.totalVulnerabilities = this.vulnerabilities.length;
            this.stats.vulnsBySeverity[data.severity]++;

            this.updateChart();
            this.applyFilters();

            const emoji = this.getSeverityEmoji(data.severity);
            this.addToFeed('vulnerability', `${emoji} ${data.severity.toUpperCase()} ${data.type} found in ${data.url}`);

            // Show notification for critical/high
            if (data.severity === 'critical' || data.severity === 'high') {
                this.showNotification(data);
            }
        },

        handleStatusUpdate(data) {
            this.status = data;
            this.addToFeed('status', data.message);
        },

        handleStatsUpdate(data) {
            this.stats = data;
            this.updateChart();
        },

        handlePortUpdate(data) {
            this.openPorts.push(data);
            this.stats.openPorts = this.openPorts.length;
            this.addToFeed('port', `🔌 Open port found: ${data.host}:${data.port} (${data.service})`);
        },

        // Chart
        initChart() {
            const ctx = document.getElementById('vulnChart');
            if (!ctx) return;

            this.vulnChart = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ff3b3b',
                            '#ff8c42',
                            '#ffd93d',
                            '#6bcf7f',
                            '#5b8def'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    cutout: '70%'
                }
            });
        },

        updateChart() {
            if (!this.vulnChart) return;

            this.vulnChart.data.datasets[0].data = [
                this.stats.vulnsBySeverity.critical,
                this.stats.vulnsBySeverity.high,
                this.stats.vulnsBySeverity.medium,
                this.stats.vulnsBySeverity.low,
                this.stats.vulnsBySeverity.info
            ];
            this.vulnChart.update();
        },

        // Load initial data from API
        async loadInitialData() {
            try {
                const [statsRes, subdomainsRes, vulnsRes] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/subdomains'),
                    fetch('/api/vulnerabilities')
                ]);

                this.stats = await statsRes.json();
                this.subdomains = await subdomainsRes.json();
                this.vulnerabilities = await vulnsRes.json();

                this.updateChart();
                this.applyFilters();
            } catch (error) {
                console.error('Error loading data:', error);
            }
        },

        // Timer
        startTimer() {
            const startTime = Date.now();
            setInterval(() => {
                const elapsed = Date.now() - startTime;
                const minutes = Math.floor(elapsed / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                this.status.elapsedTime = `${minutes}m ${seconds}s`;
            }, 1000);
        },

        // Live Feed
        addToFeed(type, message) {
            this.liveFeed.unshift({
                type,
                message,
                timestamp: new Date()
            });

            // Keep last 100 entries
            if (this.liveFeed.length > 100) {
                this.liveFeed.pop();
            }

            // Auto-scroll if enabled
            if (this.autoScroll) {
                this.$nextTick(() => {
                    const feed = document.getElementById('liveFeed');
                    if (feed) {
                        feed.scrollTop = 0;
                    }
                });
            }
        },

        // Filters
        applyFilters() {
            this.filteredVulnerabilities = this.vulnerabilities.filter(vuln => {
                if (this.filters.severity && vuln.severity !== this.filters.severity) {
                    return false;
                }
                if (this.filters.type && vuln.type !== this.filters.type) {
                    return false;
                }
                if (this.filters.search) {
                    const search = this.filters.search.toLowerCase();
                    return vuln.url.toLowerCase().includes(search) ||
                           vuln.endpoint.toLowerCase().includes(search) ||
                           vuln.description.toLowerCase().includes(search);
                }
                return true;
            });
        },

        filterByStatus(code) {
            // TODO: Implement status code filtering
            console.log('Filter by status:', code);
        },

        // Actions
        copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                this.addToFeed('status', `✓ Copied: ${text}`);
            });
        },

        copyAllSubdomains() {
            const text = this.subdomains.map(s => s.subdomain).join('\n');
            this.copyToClipboard(text);
        },

        openURL(subdomain) {
            window.open(`http://${subdomain}`, '_blank');
        },

        expandVuln(vuln) {
            // TODO: Show vulnerability details modal
            console.log('Expand vulnerability:', vuln);
        },

        async exportData(format) {
            try {
                const response = await fetch(`/api/export?format=${format}`);
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `pinakastra_scan_${Date.now()}.${format}`;
                a.click();
                window.URL.revokeObjectURL(url);
                this.showExportMenu = false;
            } catch (error) {
                console.error('Export error:', error);
            }
        },

        // Notifications
        showNotification(vuln) {
            if ('Notification' in window && Notification.permission === 'granted') {
                new Notification('🔱 Pinakastra - Critical Finding', {
                    body: `${vuln.severity.toUpperCase()} ${vuln.type} found in ${vuln.url}`,
                    icon: '/static/assets/logo.png'
                });
            } else if (Notification.permission !== 'denied') {
                Notification.requestPermission();
            }
        },

        // Helpers
        formatTime(timestamp) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString();
        },

        truncateURL(url, maxLength = 50) {
            if (url.length <= maxLength) return url;
            return url.substring(0, maxLength) + '...';
        },

        getSeverityEmoji(severity) {
            const emojis = {
                critical: '🔴',
                high: '🟠',
                medium: '🟡',
                low: '🔵',
                info: '⚪'
            };
            return emojis[severity] || '⚪';
        }
    };
}

// Request notification permission on load
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}
