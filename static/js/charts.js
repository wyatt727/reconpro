// Charts functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    const vulnerabilityChart = initVulnerabilityChart();
    const scanProgressChart = initScanProgressChart();
    const timelineChart = initTimelineChart();

    // WebSocket connection for real-time updates
    const ws = new WebSocket(`ws://${window.location.host}/ws`);
    
    ws.onmessage = function(event) {
        const data = JSON.parse(event.data);
        updateCharts(data);
    };

    function initVulnerabilityChart() {
        const ctx = document.getElementById('vulnerabilityChart').getContext('2d');
        return new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        '#dc3545', // High - Red
                        '#ffc107', // Medium - Yellow
                        '#17a2b8', // Low - Cyan
                        '#6c757d'  // Info - Gray
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    function initScanProgressChart() {
        const ctx = document.getElementById('scanProgressChart').getContext('2d');
        return new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['URLs Scanned', 'Vulnerabilities', 'Subdomains'],
                datasets: [{
                    label: 'Current Scan Progress',
                    data: [0, 0, 0],
                    backgroundColor: '#0d6efd'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    function initTimelineChart() {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        return new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Vulnerabilities Over Time',
                    data: [],
                    borderColor: '#0d6efd',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    function updateCharts(data) {
        if (data.event === 'vulnerability_found') {
            updateVulnerabilityChart(data.data.vulnerability);
        } else if (data.event === 'scan_progress') {
            updateScanProgressChart(data.data);
        }
        updateTimelineChart(data);
    }

    function updateVulnerabilityChart(vulnerability) {
        const severityIndex = {
            'high': 0,
            'medium': 1,
            'low': 2,
            'info': 3
        };
        
        const index = severityIndex[vulnerability.severity.toLowerCase()];
        vulnerabilityChart.data.datasets[0].data[index]++;
        vulnerabilityChart.update();
    }

    function updateScanProgressChart(progress) {
        scanProgressChart.data.datasets[0].data = [
            progress.urls_scanned,
            progress.vulnerabilities_found,
            progress.subdomains_found
        ];
        scanProgressChart.update();
    }

    function updateTimelineChart(data) {
        const now = new Date().toLocaleTimeString();
        
        if (timelineChart.data.labels.length > 20) {
            timelineChart.data.labels.shift();
            timelineChart.data.datasets[0].data.shift();
        }
        
        timelineChart.data.labels.push(now);
        timelineChart.data.datasets[0].data.push(data.data.vulnerabilities_found || 0);
        timelineChart.update();
    }
}); 