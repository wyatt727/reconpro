// Analytics module for handling charts and data visualization
const Analytics = {
    init() {
        this.charts = {};
        this.initCharts();
        this.initEventListeners();
        this.loadData('30d'); // Default to 30 days
    },

    initCharts() {
        // Register Chart.js plugins
        Chart.register(ChartDataLabels);

        // Set default options
        Chart.defaults.font.family = getComputedStyle(document.body).getPropertyValue('--bs-body-font-family');
        Chart.defaults.color = getComputedStyle(document.body).getPropertyValue('--bs-body-color');
        Chart.defaults.plugins.datalabels.color = getComputedStyle(document.body).getPropertyValue('--bs-body-color');

        // Initialize all charts
        this.initTrendChart();
        this.initSeverityChart();
        this.initTypeChart();
        this.initMethodChart();
        this.initResponseTimeChart();
        this.initParameterChart();
    },

    initEventListeners() {
        // Date range buttons
        document.querySelectorAll('[data-range]').forEach(button => {
            button.addEventListener('click', (e) => {
                // Update active state
                document.querySelectorAll('[data-range]').forEach(btn => {
                    btn.classList.remove('active');
                });
                e.target.classList.add('active');

                // Load data for selected range
                this.loadData(e.target.dataset.range);
            });
        });

        // Export button
        document.getElementById('exportBtn')?.addEventListener('click', () => {
            const modal = new bootstrap.Modal(document.getElementById('exportModal'));
            modal.show();
        });

        // Date range select in export modal
        const dateRangeSelect = document.querySelector('select[name="dateRange"]');
        const customDateRange = document.querySelector('.date-range');
        
        dateRangeSelect?.addEventListener('change', (e) => {
            if (e.target.value === 'custom') {
                customDateRange.classList.remove('d-none');
            } else {
                customDateRange.classList.add('d-none');
            }
        });
    },

    async loadData(range) {
        try {
            const response = await fetch(`/api/analytics?range=${range}`);
            const data = await response.json();
            
            if (response.ok) {
                this.updateCharts(data);
            } else {
                throw new Error(data.message || 'Failed to load analytics data');
            }
        } catch (error) {
            Notifications.error(error.message);
        }
    },

    updateCharts(data) {
        // Update trend chart
        this.charts.trend.data.labels = data.trends.map(t => t.date);
        this.charts.trend.data.datasets[0].data = data.trends.map(t => t.count);
        this.charts.trend.update();

        // Update severity chart
        this.charts.severity.data.datasets[0].data = [
            data.severity.critical,
            data.severity.high,
            data.severity.medium,
            data.severity.low,
            data.severity.info
        ];
        this.charts.severity.update();

        // Update type chart
        this.charts.type.data.labels = Object.keys(data.types);
        this.charts.type.data.datasets[0].data = Object.values(data.types);
        this.charts.type.update();

        // Update method chart
        this.charts.method.data.datasets[0].data = [
            data.methods.GET,
            data.methods.POST,
            data.methods.PUT,
            data.methods.DELETE,
            data.methods.OTHER
        ];
        this.charts.method.update();

        // Update response time chart
        this.charts.responseTime.data.labels = data.responseTimes.map(t => t.range);
        this.charts.responseTime.data.datasets[0].data = data.responseTimes.map(t => t.count);
        this.charts.responseTime.update();

        // Update parameter chart
        this.charts.parameter.data.labels = data.parameters.map(p => p.name);
        this.charts.parameter.data.datasets[0].data = data.parameters.map(p => p.count);
        this.charts.parameter.update();
    },

    initTrendChart() {
        const ctx = document.getElementById('trendChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Vulnerabilities',
                    data: [],
                    borderColor: getComputedStyle(document.documentElement).getPropertyValue('--bs-primary'),
                    backgroundColor: `${getComputedStyle(document.documentElement).getPropertyValue('--bs-primary')}33`,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    datalabels: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    },

    initSeverityChart() {
        const ctx = document.getElementById('severityChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#dc3545', // Critical
                        '#ffc107', // High
                        '#0d6efd', // Medium
                        '#0dcaf0', // Low
                        '#6c757d'  // Info
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    datalabels: {
                        color: '#fff',
                        formatter: (value, ctx) => {
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total ? ((value / total) * 100).toFixed(1) + '%' : '0%';
                            return percentage;
                        }
                    }
                }
            }
        });
    },

    initTypeChart() {
        const ctx = document.getElementById('typeChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.type = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bs-primary')
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    datalabels: {
                        anchor: 'end',
                        align: 'top'
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    },

    initMethodChart() {
        const ctx = document.getElementById('methodChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.method = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['GET', 'POST', 'PUT', 'DELETE', 'OTHER'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#198754', // GET
                        '#0d6efd', // POST
                        '#ffc107', // PUT
                        '#dc3545', // DELETE
                        '#6c757d'  // OTHER
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    datalabels: {
                        color: '#fff',
                        formatter: (value, ctx) => {
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total ? ((value / total) * 100).toFixed(1) + '%' : '0%';
                            return percentage;
                        }
                    }
                }
            }
        });
    },

    initResponseTimeChart() {
        const ctx = document.getElementById('responseTimeChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.responseTime = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bs-info')
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    datalabels: {
                        anchor: 'end',
                        align: 'top'
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    },

    initParameterChart() {
        const ctx = document.getElementById('parameterChart')?.getContext('2d');
        if (!ctx) return;

        this.charts.parameter = new Chart(ctx, {
            type: 'horizontalBar',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: getComputedStyle(document.documentElement).getPropertyValue('--bs-success')
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: {
                    legend: {
                        display: false
                    },
                    datalabels: {
                        anchor: 'end',
                        align: 'right'
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    },
                    y: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }
};

// Initialize analytics when DOM is loaded
document.addEventListener('DOMContentLoaded', () => Analytics.init()); 