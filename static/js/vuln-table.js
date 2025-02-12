// Vulnerability table management module
const VulnTable = {
    init() {
        this.table = document.getElementById('vulnTable');
        this.pagination = document.querySelector('.pagination');
        this.currentPage = 1;
        this.itemsPerPage = 10;
        this.vulnerabilities = [];
        
        this.initEventListeners();
        this.loadVulnerabilities();
    },

    initEventListeners() {
        // Refresh button
        document.getElementById('refreshVulns')?.addEventListener('click', () => {
            this.loadVulnerabilities();
        });

        // Export button
        document.getElementById('exportVulns')?.addEventListener('click', () => {
            this.exportVulnerabilities();
        });

        // Table row click
        this.table?.addEventListener('click', (e) => {
            const row = e.target.closest('tr');
            if (row && row.dataset.vulnId) {
                this.showVulnerabilityDetails(row.dataset.vulnId);
            }
        });
    },

    async loadVulnerabilities() {
        try {
            const response = await fetch('/api/vulnerabilities');
            const data = await response.json();
            
            if (response.ok) {
                this.vulnerabilities = data.vulnerabilities;
                this.renderTable();
                this.renderPagination();
            } else {
                throw new Error(data.message || 'Failed to load vulnerabilities');
            }
        } catch (error) {
            Notifications.error(error.message);
        }
    },

    renderTable() {
        if (!this.table) return;

        // Calculate pagination
        const start = (this.currentPage - 1) * this.itemsPerPage;
        const end = start + this.itemsPerPage;
        const pageItems = this.vulnerabilities.slice(start, end);

        // Clear existing rows
        this.table.innerHTML = '';

        if (pageItems.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td colspan="5" class="text-center py-4">
                    <i class="fas fa-search fa-2x text-muted mb-2"></i>
                    <p class="text-muted mb-0">No vulnerabilities found</p>
                </td>
            `;
            this.table.appendChild(row);
            return;
        }

        // Add new rows
        pageItems.forEach(vuln => {
            const row = document.createElement('tr');
            row.dataset.vulnId = vuln.id;
            row.innerHTML = `
                <td>
                    <span class="badge bg-${this.getSeverityClass(vuln.severity)}">
                        ${vuln.severity}
                    </span>
                </td>
                <td class="text-break">
                    <div class="d-flex align-items-center">
                        <i class="fas fa-${this.getMethodIcon(vuln.method)} text-muted me-2"></i>
                        ${this.truncateUrl(vuln.url)}
                    </div>
                </td>
                <td>
                    <span class="badge bg-secondary">
                        ${vuln.type}
                    </span>
                </td>
                <td>${vuln.parameter}</td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary" onclick="VulnTable.showVulnerabilityDetails('${vuln.id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-outline-success" onclick="VulnTable.retestVulnerability('${vuln.id}')">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                        <button class="btn btn-outline-danger" onclick="VulnTable.deleteVulnerability('${vuln.id}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            `;
            this.table.appendChild(row);
        });
    },

    renderPagination() {
        if (!this.pagination) return;

        const totalPages = Math.ceil(this.vulnerabilities.length / this.itemsPerPage);
        
        // Clear existing pagination
        this.pagination.innerHTML = '';

        // Previous button
        this.pagination.appendChild(this.createPaginationItem('Previous', this.currentPage > 1, () => {
            this.currentPage--;
            this.renderTable();
            this.renderPagination();
        }));

        // Page numbers
        for (let i = 1; i <= totalPages; i++) {
            this.pagination.appendChild(this.createPaginationItem(i, true, () => {
                this.currentPage = i;
                this.renderTable();
                this.renderPagination();
            }, i === this.currentPage));
        }

        // Next button
        this.pagination.appendChild(this.createPaginationItem('Next', this.currentPage < totalPages, () => {
            this.currentPage++;
            this.renderTable();
            this.renderPagination();
        }));
    },

    createPaginationItem(text, enabled, onClick, active = false) {
        const li = document.createElement('li');
        li.className = `page-item${active ? ' active' : ''}${!enabled ? ' disabled' : ''}`;
        
        const a = document.createElement('a');
        a.className = 'page-link';
        a.href = '#';
        a.textContent = text;
        
        if (enabled) {
            a.addEventListener('click', (e) => {
                e.preventDefault();
                onClick();
            });
        }
        
        li.appendChild(a);
        return li;
    },

    async showVulnerabilityDetails(id) {
        try {
            const response = await fetch(`/api/vulnerabilities/${id}`);
            const data = await response.json();
            
            if (response.ok) {
                const modal = document.getElementById('vulnDetailsModal');
                const modalBody = modal.querySelector('.modal-body');
                
                modalBody.innerHTML = this.generateVulnerabilityDetails(data.vulnerability);
                
                new bootstrap.Modal(modal).show();
            } else {
                throw new Error(data.message || 'Failed to load vulnerability details');
            }
        } catch (error) {
            Notifications.error(error.message);
        }
    },

    generateVulnerabilityDetails(vuln) {
        return `
            <div class="mb-4">
                <h6 class="text-muted mb-2">URL</h6>
                <div class="d-flex align-items-center">
                    <span class="badge bg-${this.getMethodClass(vuln.method)} me-2">${vuln.method}</span>
                    <span class="text-break">${vuln.url}</span>
                </div>
            </div>
            <div class="row mb-4">
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Parameter</h6>
                    <p class="mb-0">${vuln.parameter}</p>
                </div>
                <div class="col-md-6">
                    <h6 class="text-muted mb-2">Payload</h6>
                    <code class="d-block p-2 bg-light">${vuln.payload}</code>
                </div>
            </div>
            <div class="row mb-4">
                <div class="col-md-4">
                    <h6 class="text-muted mb-2">Response Time</h6>
                    <p class="mb-0">${vuln.response_time}ms</p>
                </div>
                <div class="col-md-4">
                    <h6 class="text-muted mb-2">Status Code</h6>
                    <p class="mb-0">${vuln.status_code}</p>
                </div>
                <div class="col-md-4">
                    <h6 class="text-muted mb-2">Content Length</h6>
                    <p class="mb-0">${vuln.content_length} bytes</p>
                </div>
            </div>
            <div class="mb-4">
                <h6 class="text-muted mb-2">GF Matches</h6>
                <div class="d-flex flex-wrap gap-2">
                    ${vuln.gf_matches.map(match => `
                        <span class="badge bg-secondary">${match}</span>
                    `).join('')}
                </div>
            </div>
            <div class="mb-4">
                <h6 class="text-muted mb-2">Nuclei Output</h6>
                <pre class="bg-light p-2 mb-0"><code>${vuln.nuclei_output}</code></pre>
            </div>
            <div>
                <h6 class="text-muted mb-2">Error Patterns</h6>
                <ul class="list-unstyled mb-0">
                    ${vuln.error_patterns.map(pattern => `
                        <li><i class="fas fa-exclamation-triangle text-warning me-2"></i>${pattern}</li>
                    `).join('')}
                </ul>
            </div>
        `;
    },

    async retestVulnerability(id) {
        try {
            const response = await fetch(`/api/vulnerabilities/${id}/retest`, {
                method: 'POST'
            });
            const data = await response.json();
            
            if (response.ok) {
                Notifications.success('Vulnerability retest initiated');
            } else {
                throw new Error(data.message || 'Failed to retest vulnerability');
            }
        } catch (error) {
            Notifications.error(error.message);
        }
    },

    async deleteVulnerability(id) {
        if (!confirm('Are you sure you want to delete this vulnerability?')) {
            return;
        }

        try {
            const response = await fetch(`/api/vulnerabilities/${id}`, {
                method: 'DELETE'
            });
            const data = await response.json();
            
            if (response.ok) {
                this.vulnerabilities = this.vulnerabilities.filter(v => v.id !== id);
                this.renderTable();
                this.renderPagination();
                Notifications.success('Vulnerability deleted successfully');
            } else {
                throw new Error(data.message || 'Failed to delete vulnerability');
            }
        } catch (error) {
            Notifications.error(error.message);
        }
    },

    async exportVulnerabilities() {
        try {
            const response = await fetch('/api/vulnerabilities/export');
            const blob = await response.blob();
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vulnerabilities_${new Date().toISOString()}.csv`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            Notifications.success('Vulnerabilities exported successfully');
        } catch (error) {
            Notifications.error('Failed to export vulnerabilities');
        }
    },

    addVulnerability(vuln) {
        this.vulnerabilities.unshift(vuln);
        this.renderTable();
        this.renderPagination();
    },

    getSeverityClass(severity) {
        switch (severity.toLowerCase()) {
            case 'critical':
                return 'danger';
            case 'high':
                return 'warning';
            case 'medium':
                return 'primary';
            case 'low':
                return 'info';
            default:
                return 'secondary';
        }
    },

    getMethodClass(method) {
        switch (method.toUpperCase()) {
            case 'GET':
                return 'success';
            case 'POST':
                return 'primary';
            case 'PUT':
                return 'warning';
            case 'DELETE':
                return 'danger';
            default:
                return 'secondary';
        }
    },

    getMethodIcon(method) {
        switch (method.toUpperCase()) {
            case 'GET':
                return 'arrow-down';
            case 'POST':
                return 'arrow-up';
            case 'PUT':
                return 'arrow-right';
            case 'DELETE':
                return 'times';
            default:
                return 'circle';
        }
    },

    truncateUrl(url, maxLength = 50) {
        if (url.length <= maxLength) return url;
        return url.substring(0, maxLength - 3) + '...';
    }
};

// Initialize vulnerability table when DOM is loaded
document.addEventListener('DOMContentLoaded', () => VulnTable.init()); 