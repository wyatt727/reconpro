/*!
 * WebSocket handler for ReconPro
 */

// WebSocket management module
const WebSocketManager = {
    init() {
        this.connect();
        this.initReconnection();
    },

    connect() {
        this.ws = new WebSocket(`ws://${window.location.host}/ws`);
        this.addEventListeners();
    },

    addEventListeners() {
        this.ws.onopen = () => {
            console.log('WebSocket connected');
            this.clearReconnectTimer();
            Notifications.success('Connected to real-time updates');
            
            // Update connection status
            document.querySelectorAll('.connection-status').forEach(el => {
                el.innerHTML = '<i class="fas fa-circle text-success me-2"></i>Connected';
            });
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            this.scheduleReconnection();
            Notifications.warning('Disconnected from real-time updates');
            
            // Update connection status
            document.querySelectorAll('.connection-status').forEach(el => {
                el.innerHTML = '<i class="fas fa-circle text-warning me-2"></i>Reconnecting...';
            });
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            Notifications.error('WebSocket connection error');
            
            // Update connection status
            document.querySelectorAll('.connection-status').forEach(el => {
                el.innerHTML = '<i class="fas fa-circle text-danger me-2"></i>Connection Error';
            });
        };

        this.ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };
    },

    handleMessage(data) {
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
            case 'status_update':
                this.handleStatusUpdate(data);
                break;
            case 'error':
                this.handleError(data);
                break;
            default:
                console.warn('Unknown WebSocket event:', data.event);
        }
    },

    handleScanStarted(data) {
        // Update UI elements
        document.getElementById('scanBtn')?.classList.add('d-none');
        document.getElementById('stopBtn')?.classList.remove('d-none');
        
        // Reset progress
        const progressBar = document.querySelector('#scanProgress .progress-bar');
        if (progressBar) {
            progressBar.style.width = '0%';
            progressBar.setAttribute('aria-valuenow', '0');
        }

        // Reset counters
        document.getElementById('urlCount').textContent = '0';
        document.getElementById('subdomainCount').textContent = '0';
        document.getElementById('vulnCount').textContent = '0';

        // Show notification
        Notifications.info('Scan started', data.message);

        // Add to activity log
        this.addActivityLogEntry('scan_started', data.message);
    },

    handleScanProgress(data) {
        // Update progress bar
        const progressBar = document.querySelector('#scanProgress .progress-bar');
        if (progressBar) {
            progressBar.style.width = `${data.progress}%`;
            progressBar.setAttribute('aria-valuenow', data.progress);
        }

        // Update counters
        document.getElementById('urlCount').textContent = data.urls_scanned;
        document.getElementById('subdomainCount').textContent = data.subdomains_found;
        document.getElementById('vulnCount').textContent = data.vulnerabilities_found;

        // Update status text
        document.getElementById('scanStatus').textContent = data.status;

        // Add to activity log if significant progress
        if (data.progress % 10 === 0) {  // Every 10%
            this.addActivityLogEntry('scan_progress', `Scan progress: ${data.progress}%`);
        }
    },

    handleScanCompleted(data) {
        // Update UI elements
        document.getElementById('scanBtn')?.classList.remove('d-none');
        document.getElementById('stopBtn')?.classList.add('d-none');

        // Show notification
        Notifications.success('Scan completed', data.message);

        // Add to activity log
        this.addActivityLogEntry('scan_completed', data.message);

        // Refresh vulnerability table
        if (window.VulnTable) {
            window.VulnTable.loadVulnerabilities();
        }

        // Refresh analytics
        if (window.Analytics) {
            window.Analytics.loadData('30d');
        }
    },

    handleVulnerabilityFound(data) {
        // Update vulnerability table
        if (window.VulnTable) {
            window.VulnTable.addVulnerability(data.vulnerability);
        }

        // Update counter
        const vulnCount = document.getElementById('vulnCount');
        if (vulnCount) {
            vulnCount.textContent = parseInt(vulnCount.textContent) + 1;
        }

        // Show notification
        Notifications.warning(
            'Vulnerability Found',
            `${data.vulnerability.type} found in ${data.vulnerability.url}`
        );

        // Add to activity log
        this.addActivityLogEntry('vulnerability_found', 
            `Found ${data.vulnerability.type} vulnerability in ${data.vulnerability.parameter}`
        );
    },

    handleStatusUpdate(data) {
        // Update statistics
        if (window.Analytics) {
            window.Analytics.updateCharts(data);
        }
    },

    handleError(data) {
        console.error('WebSocket error event:', data);
        Notifications.error('Error', data.message);
        
        // Add to activity log
        this.addActivityLogEntry('error', data.message);
    },

    addActivityLogEntry(type, message) {
        const activityLog = document.getElementById('activityLog');
        if (!activityLog) return;

        const entry = document.createElement('div');
        entry.className = 'list-group-item';
        
        const icon = this.getActivityIcon(type);
        const time = new Date().toLocaleTimeString();
        
        entry.innerHTML = `
            <div class="d-flex w-100 justify-content-between">
                <div>
                    <i class="${icon.class} ${icon.color} me-2"></i>
                    ${message}
                </div>
                <small class="text-muted">${time}</small>
            </div>
        `;

        activityLog.insertBefore(entry, activityLog.firstChild);

        // Limit to last 50 entries
        while (activityLog.children.length > 50) {
            activityLog.removeChild(activityLog.lastChild);
        }
    },

    getActivityIcon(type) {
        switch (type) {
            case 'scan_started':
                return { class: 'fas fa-play', color: 'text-success' };
            case 'scan_completed':
                return { class: 'fas fa-check', color: 'text-success' };
            case 'scan_progress':
                return { class: 'fas fa-sync', color: 'text-primary' };
            case 'vulnerability_found':
                return { class: 'fas fa-bug', color: 'text-warning' };
            case 'error':
                return { class: 'fas fa-exclamation-circle', color: 'text-danger' };
            default:
                return { class: 'fas fa-info-circle', color: 'text-info' };
        }
    },

    initReconnection() {
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 1000; // Start with 1 second
        this.maxReconnectDelay = 30000; // Max 30 seconds
    },

    scheduleReconnection() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.log('Max reconnection attempts reached');
            Notifications.error('Failed to reconnect to server');
            return;
        }

        // Calculate delay with exponential backoff
        const delay = Math.min(
            this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
            this.maxReconnectDelay
        );

        console.log(`Scheduling reconnection attempt ${this.reconnectAttempts + 1} in ${delay}ms`);
        
        this.reconnectTimer = setTimeout(() => {
            this.reconnectAttempts++;
            this.connect();
        }, delay);
    },

    clearReconnectTimer() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        this.reconnectAttempts = 0;
    },

    send(data) {
        if (this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
        } else {
            console.warn('WebSocket is not connected');
            Notifications.warning('Cannot send message - WebSocket is not connected');
        }
    }
};

// Initialize WebSocket manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => WebSocketManager.init()); 