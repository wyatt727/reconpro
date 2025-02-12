// Scan management module
const ScanManager = {
    init() {
        this.scanQueue = new Map();
        this.activeScans = new Map();
        this.initEventListeners();
        this.loadScans();
        this.startPolling();
    },

    initEventListeners() {
        // New scan form submission
        document.getElementById('startScanBtn')?.addEventListener('click', () => {
            this.submitNewScan();
        });

        // Scan queue table actions
        document.getElementById('scanQueueTable')?.addEventListener('click', (e) => {
            const action = e.target.closest('button')?.dataset.action;
            const scanId = e.target.closest('tr')?.dataset.scanId;
            
            if (action && scanId) {
                switch (action) {
                    case 'pause':
                        this.pauseScan(scanId);
                        break;
                    case 'resume':
                        this.resumeScan(scanId);
                        break;
                    case 'stop':
                        this.stopScan(scanId);
                        break;
                    case 'details':
                        this.showScanDetails(scanId);
                        break;
                }
            }
        });

        // WebSocket event handling
        WebSocketManager.addMessageHandler('scan_progress', (data) => {
            this.updateScanProgress(data);
        });
    },

    async loadScans() {
        try {
            const response = await fetch('/api/scans');
            const data = await response.json();
            
            // Update active scans
            this.activeScans.clear();
            Object.entries(data.active_scans).forEach(([id, scan]) => {
                this.activeScans.set(id, scan);
            });

            // Update scan history
            this.scanQueue.clear();
            Object.entries(data.scan_history).forEach(([id, scan]) => {
                this.scanQueue.set(id, scan);
            });

            this.updateUI();
        } catch (error) {
            console.error('Error loading scans:', error);
            Notifications.error('Failed to load scans');
        }
    },

    startPolling() {
        // Poll for updates every 5 seconds
        setInterval(() => this.loadScans(), 5000);
    },

    async submitNewScan() {
        const form = document.getElementById('newScanForm');
        const formData = new FormData(form);
        
        // Build config object
        const config = {};
        for (const [key, value] of formData.entries()) {
            if (key.startsWith('config.')) {
                const configKey = key.replace('config.', '');
                config[configKey] = value;
            }
        }

        const data = {
            domain: formData.get('domain'),
            priority: parseInt(formData.get('priority')),
            config: config
        };

        try {
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                const result = await response.json();
                bootstrap.Modal.getInstance(document.getElementById('newScanModal')).hide();
                form.reset();
                Notifications.success('Scan added to queue');
                await this.loadScans();
            } else {
                throw new Error(await response.text());
            }
        } catch (error) {
            console.error('Error submitting scan:', error);
            Notifications.error('Failed to submit scan');
        }
    },

    async pauseScan(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}/pause`, {
                method: 'POST'
            });
            
            if (response.ok) {
                Notifications.success('Scan paused');
                await this.loadScans();
            } else {
                throw new Error(await response.text());
            }
        } catch (error) {
            console.error('Error pausing scan:', error);
            Notifications.error('Failed to pause scan');
        }
    },

    async resumeScan(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}/resume`, {
                method: 'POST'
            });
            
            if (response.ok) {
                Notifications.success('Scan resumed');
                await this.loadScans();
            } else {
                throw new Error(await response.text());
            }
        } catch (error) {
            console.error('Error resuming scan:', error);
            Notifications.error('Failed to resume scan');
        }
    },

    async stopScan(scanId) {
        if (!confirm('Are you sure you want to stop this scan?')) {
            return;
        }

        try {
            const response = await fetch(`/api/scans/${scanId}`, {
                method: 'DELETE'
            });
            
            if (response.ok) {
                Notifications.success('Scan stopped');
                await this.loadScans();
            } else {
                throw new Error(await response.text());
            }
        } catch (error) {
            console.error('Error stopping scan:', error);
            Notifications.error('Failed to stop scan');
        }
    },

    async showScanDetails(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}`);
            const data = await response.json();
            
            const modalBody = document.querySelector('#scanDetailsModal .modal-body');
            modalBody.innerHTML = this.generateScanDetailsHTML(data);
            
            new bootstrap.Modal(document.getElementById('scanDetailsModal')).show();
        } catch (error) {
            console.error('Error loading scan details:', error);
            Notifications.error('Failed to load scan details');
        }
    },

    updateScanProgress(data) {
        const scan = this.activeScans.get(data.scan_id);
        if (scan) {
            scan.status = data.status;
            scan.progress = data.progress;
            this.updateUI();
        }
    },

    updateUI() {
        const table = document.getElementById('scanQueueTable');
        if (!table) return;

        // Clear existing rows
        table.innerHTML = '';

        // Add active scans
        this.activeScans.forEach(scan => {
            table.appendChild(this.createScanRow(scan));
        });

        // Add queued scans
        this.scanQueue.forEach(scan => {
            if (scan.status === 'queued') {
                table.appendChild(this.createScanRow(scan));
            }
        });

        // Update counters
        document.getElementById('activeScanCount').textContent = this.activeScans.size;
    },

    createScanRow(scan) {
        const row = document.createElement('tr');
        row.dataset.scanId = scan.scan_id;
        
        row.innerHTML = `
            <td>${scan.domain}</td>
            <td>
                <span class="badge bg-${this.getStatusClass(scan.status)}">
                    ${scan.status}
                </span>
            </td>
            <td>
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar progress-bar-striped progress-bar-animated"
                         role="progressbar"
                         style="width: ${scan.progress}%"
                         aria-valuenow="${scan.progress}"
                         aria-valuemin="0"
                         aria-valuemax="100">
                        ${Math.round(scan.progress)}%
                    </div>
                </div>
            </td>
            <td>
                <span class="badge bg-${this.getPriorityClass(scan.priority)}">
                    ${this.getPriorityLabel(scan.priority)}
                </span>
            </td>
            <td>${new Date(scan.timestamp).toLocaleString()}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    ${this.getActionButtons(scan)}
                </div>
            </td>
        `;
        
        return row;
    },

    getStatusClass(status) {
        switch (status.toLowerCase()) {
            case 'running':
                return 'primary';
            case 'completed':
                return 'success';
            case 'error':
                return 'danger';
            case 'paused':
                return 'warning';
            case 'queued':
                return 'secondary';
            default:
                return 'info';
        }
    },

    getPriorityClass(priority) {
        switch (priority) {
            case 1:
                return 'danger';
            case 2:
                return 'primary';
            case 3:
                return 'secondary';
            default:
                return 'info';
        }
    },

    getPriorityLabel(priority) {
        switch (priority) {
            case 1:
                return 'High';
            case 2:
                return 'Normal';
            case 3:
                return 'Low';
            default:
                return 'Unknown';
        }
    },

    getActionButtons(scan) {
        const buttons = [];

        if (scan.status === 'running') {
            buttons.push(`
                <button class="btn btn-warning" data-action="pause">
                    <i class="fas fa-pause"></i>
                </button>
            `);
            buttons.push(`
                <button class="btn btn-danger" data-action="stop">
                    <i class="fas fa-stop"></i>
                </button>
            `);
        } else if (scan.status === 'paused') {
            buttons.push(`
                <button class="btn btn-primary" data-action="resume">
                    <i class="fas fa-play"></i>
                </button>
            `);
            buttons.push(`
                <button class="btn btn-danger" data-action="stop">
                    <i class="fas fa-stop"></i>
                </button>
            `);
        }

        buttons.push(`
            <button class="btn btn-info" data-action="details">
                <i class="fas fa-info-circle"></i>
            </button>
        `);

        return buttons.join('');
    },

    generateScanDetailsHTML(scan) {
        return `
            <div class="mb-4">
                <h6 class="text-muted mb-2">Domain</h6>
                <p class="mb-0">${scan.domain}</p>
            </div>
            <div class="row mb-4">
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Status</h6>
                    <span class="badge bg-${this.getStatusClass(scan.status)}">
                        ${scan.status}
                    </span>
                </div>
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Priority</h6>
                    <span class="badge bg-${this.getPriorityClass(scan.priority)}">
                        ${this.getPriorityLabel(scan.priority)}
                    </span>
                </div>
            </div>
            <div class="mb-4">
                <h6 class="text-muted mb-2">Progress</h6>
                <div class="progress" style="height: 25px;">
                    <div class="progress-bar progress-bar-striped progress-bar-animated"
                         role="progressbar"
                         style="width: ${scan.progress}%"
                         aria-valuenow="${scan.progress}"
                         aria-valuemin="0"
                         aria-valuemax="100">
                        ${Math.round(scan.progress)}%
                    </div>
                </div>
            </div>
            <div class="row mb-4">
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Started</h6>
                    <p class="mb-0">${new Date(scan.timestamp).toLocaleString()}</p>
                </div>
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Duration</h6>
                    <p class="mb-0">${this.formatDuration(scan.duration)}</p>
                </div>
            </div>
            ${scan.config ? `
                <div class="mb-4">
                    <h6 class="text-muted mb-2">Configuration</h6>
                    <pre class="bg-light p-3 mb-0"><code>${JSON.stringify(scan.config, null, 2)}</code></pre>
                </div>
            ` : ''}
        `;
    },

    formatDuration(seconds) {
        if (!seconds) return 'N/A';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = Math.floor(seconds % 60);
        
        const parts = [];
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (remainingSeconds > 0) parts.push(`${remainingSeconds}s`);
        
        return parts.join(' ') || '0s';
    }
};

// Initialize scan manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => ScanManager.init()); 