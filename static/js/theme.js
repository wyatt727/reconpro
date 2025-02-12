/*!
 * Theme switcher for ReconPro
 */

// Theme management module
const Theme = {
    init() {
        this.initTheme();
        this.initEventListeners();
    },

    initTheme() {
        // Check for saved theme preference
        const savedTheme = localStorage.getItem('theme') || 'auto';
        this.setTheme(savedTheme);

        // Update theme based on system preference if set to auto
        if (savedTheme === 'auto') {
            this.updateThemeBasedOnSystem();
        }
    },

    initEventListeners() {
        // Theme toggle buttons
        document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
            toggle.addEventListener('click', () => {
                const theme = toggle.getAttribute('data-bs-theme-value');
                this.setTheme(theme);
            });
        });

        // Listen for system theme changes
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (localStorage.getItem('theme') === 'auto') {
                this.updateThemeBasedOnSystem();
            }
        });
    },

    setTheme(theme) {
        document.documentElement.setAttribute('data-bs-theme', theme);
        localStorage.setItem('theme', theme);

        // Update active state of theme toggle buttons
        document.querySelectorAll('[data-bs-theme-value]').forEach(element => {
            element.classList.toggle('active', element.getAttribute('data-bs-theme-value') === theme);
        });

        // Update theme icon
        const themeIcon = document.querySelector('.theme-icon-active');
        if (themeIcon) {
            const isDark = theme === 'dark' || (theme === 'auto' && this.isSystemDark());
            themeIcon.classList.remove('fa-sun', 'fa-moon', 'fa-circle-half-stroke');
            themeIcon.classList.add(this.getThemeIcon(theme));
        }

        // Update charts if they exist
        if (window.Analytics?.charts) {
            this.updateChartColors();
        }
    },

    updateThemeBasedOnSystem() {
        const systemTheme = this.isSystemDark() ? 'dark' : 'light';
        document.documentElement.setAttribute('data-bs-theme', systemTheme);
        this.updateChartColors();
    },

    isSystemDark() {
        return window.matchMedia('(prefers-color-scheme: dark)').matches;
    },

    getThemeIcon(theme) {
        switch (theme) {
            case 'light':
                return 'fa-sun';
            case 'dark':
                return 'fa-moon';
            default:
                return 'fa-circle-half-stroke';
        }
    },

    updateChartColors() {
        // Get current theme colors
        const style = getComputedStyle(document.documentElement);
        const textColor = style.getPropertyValue('--bs-body-color');
        const gridColor = style.getPropertyValue('--bs-border-color');
        const primaryColor = style.getPropertyValue('--bs-primary');
        const successColor = style.getPropertyValue('--bs-success');
        const dangerColor = style.getPropertyValue('--bs-danger');
        const warningColor = style.getPropertyValue('--bs-warning');
        const infoColor = style.getPropertyValue('--bs-info');

        // Update Chart.js defaults
        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = gridColor;

        // Update all charts if they exist
        if (window.Analytics?.charts) {
            Object.values(window.Analytics.charts).forEach(chart => {
                // Update specific chart colors based on type
                switch (chart.config.type) {
                    case 'line':
                        chart.data.datasets[0].borderColor = primaryColor;
                        chart.data.datasets[0].backgroundColor = `${primaryColor}33`;
                        break;
                    case 'bar':
                        chart.data.datasets[0].backgroundColor = primaryColor;
                        break;
                    case 'doughnut':
                    case 'pie':
                        chart.data.datasets[0].backgroundColor = [
                            dangerColor,   // Critical
                            warningColor,  // High
                            primaryColor,  // Medium
                            infoColor,     // Low
                            gridColor      // Info
                        ];
                        break;
                }
                chart.update('none'); // Update without animation
            });
        }
    },

    isDark() {
        const theme = localStorage.getItem('theme');
        return theme === 'dark' || (theme === 'auto' && this.isSystemDark());
    }
};

// Initialize theme when DOM is loaded
document.addEventListener('DOMContentLoaded', () => Theme.init()); 