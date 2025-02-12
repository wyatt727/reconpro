// Core application functionality
const App = {
    init() {
        this.initTheme();
        this.initWebSocket();
        this.initEventListeners();
        this.initTooltips();
    },

    initTheme() {
        // Check for saved theme preference
        const savedTheme = localStorage.getItem('theme') || 'auto';
        document.documentElement.setAttribute('data-bs-theme', savedTheme);
    },

    initWebSocket() {
        this.ws = new WebSocket(`ws://${window.location.host}/ws`);
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            Notifications.show('Connected', 'Real-time updates enabled');
        };
        
        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            Notifications.show('Disconnected', 'Real-time updates disabled', 'warning');
            // Try to reconnect after 5 seconds
            setTimeout(() => this.initWebSocket(), 5000);
        };
        
        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            } catch (e) {
                console.error('Error handling WebSocket message:', e);
            }
        };
    },

    handleWebSocketMessage(data) {
        switch (data.event) {
            case 'scan_started':
                this.handleScanStarted(data);
                break;
            case 'scan_progress':
                this.handleScanProgress(data);
                break;
            case 'scan_completed':
                this.handleScanCompleted(data);
                break;
            case 'vulnerability_found':
                this.handleVulnerabilityFound(data);
                break;
            case 'error':
                this.handleError(data);
                break;
        }
    },

    handleScanStarted(data) {
        document.getElementById('scanBtn').classList.add('d-none');
        document.getElementById('stopBtn').classList.remove('d-none');
        document.getElementById('scanStatus').textContent = 'Scan in progress...';
        this.startScanTimer();
        Notifications.show('Scan Started', data.message);
    },

    handleScanProgress(data) {
        const progressBar = document.querySelector('#scanProgress .progress-bar');
        progressBar.style.width = `${data.progress}%`;
        progressBar.setAttribute('aria-valuenow', data.progress);
        
        // Update counters
        document.getElementById('urlCount').textContent = data.urls_scanned;
        document.getElementById('subdomainCount').textContent = data.subdomains_found;
        document.getElementById('vulnCount').textContent = data.vulnerabilities_found;
        
        document.getElementById('scanStatus').textContent = data.status;
    },

    handleScanCompleted(data) {
        document.getElementById('scanBtn').classList.remove('d-none');
        document.getElementById('stopBtn').classList.add('d-none');
        document.getElementById('scanStatus').textContent = 'Scan completed';
        this.stopScanTimer();
        Notifications.show('Scan Completed', data.message, 'success');
    },

    handleVulnerabilityFound(data) {
        // Update vulnerability table
        if (window.VulnTable) {
            window.VulnTable.addVulnerability(data.vulnerability);
        }
        
        // Update counter
        const vulnCount = document.getElementById('vulnCount');
        vulnCount.textContent = parseInt(vulnCount.textContent) + 1;
        
        // Show notification
        Notifications.show(
            'Vulnerability Found',
            `${data.vulnerability.type} found in ${data.vulnerability.url}`,
            'warning'
        );
    },

    handleError(data) {
        Notifications.show('Error', data.message, 'error');
    },

    initEventListeners() {
        // Scan button
        document.getElementById('scanBtn')?.addEventListener('click', () => {
            const modal = new bootstrap.Modal(document.getElementById('configureModal'));
            modal.show();
        });

        // Stop button
        document.getElementById('stopBtn')?.addEventListener('click', () => {
            this.stopScan();
        });

        // Configure form
        document.getElementById('startScanBtn')?.addEventListener('click', () => {
            this.startScan();
        });

        // Theme toggler
        document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const theme = toggle.getAttribute('data-bs-theme-value');
                document.documentElement.setAttribute('data-bs-theme', theme);
                localStorage.setItem('theme', theme);
            });
        });
    },

    initTooltips() {
        // Initialize all tooltips
        const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltip => new bootstrap.Tooltip(tooltip));
    },

    async startScan() {
        const form = document.getElementById('scanConfigForm');
        const formData = new FormData(form);
        
        try {
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(Object.fromEntries(formData)),
            });
            
            const data = await response.json();
            
            if (response.ok) {
                bootstrap.Modal.getInstance(document.getElementById('configureModal')).hide();
                Notifications.show('Scan Started', data.message, 'success');
            } else {
                throw new Error(data.message || 'Failed to start scan');
            }
        } catch (error) {
            Notifications.show('Error', error.message, 'error');
        }
    },

    async stopScan() {
        try {
            const response = await fetch('/api/scan/stop', {
                method: 'POST',
            });
            
            const data = await response.json();
            
            if (response.ok) {
                Notifications.show('Scan Stopped', data.message);
            } else {
                throw new Error(data.message || 'Failed to stop scan');
            }
        } catch (error) {
            Notifications.show('Error', error.message, 'error');
        }
    },

    startScanTimer() {
        this.scanStartTime = Date.now();
        this.scanTimer = setInterval(() => {
            const elapsed = Math.floor((Date.now() - this.scanStartTime) / 1000);
            const minutes = Math.floor(elapsed / 60);
            const seconds = elapsed % 60;
            document.getElementById('scanTime').textContent = 
                `Time: ${minutes}:${seconds.toString().padStart(2, '0')}`;
        }, 1000);
    },

    stopScanTimer() {
        if (this.scanTimer) {
            clearInterval(this.scanTimer);
            this.scanTimer = null;
        }
    }
};

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => App.init()); 