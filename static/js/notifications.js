/*!
 * Notification handler for ReconPro
 */

// Notifications module for handling toast notifications
const Notifications = {
    init() {
        this.container = document.querySelector('.toast-container');
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'toast-container position-fixed top-0 end-0 p-3';
            document.body.appendChild(this.container);
        }
    },

    show(title, message, type = 'info') {
        if (!this.container) {
            this.init();
        }

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');

        // Set background color based on type
        toast.classList.add(`bg-${type === 'error' ? 'danger' : type}`);
        toast.classList.add('text-white');

        // Get icon based on type
        const icon = this.getIcon(type);

        toast.innerHTML = `
            <div class="toast-header bg-${type === 'error' ? 'danger' : type} text-white">
                <i class="${icon} me-2"></i>
                <strong class="me-auto">${title}</strong>
                <small>${new Date().toLocaleTimeString()}</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        `;

        this.container.appendChild(toast);

        // Initialize and show the toast
        const bsToast = new bootstrap.Toast(toast, {
            animation: true,
            autohide: true,
            delay: this.getDelay(type)
        });
        bsToast.show();

        // Remove the toast element after it's hidden
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });

        // Play notification sound based on type
        this.playSound(type);

        return bsToast;
    },

    getIcon(type) {
        switch (type) {
            case 'success':
                return 'fas fa-check-circle';
            case 'warning':
                return 'fas fa-exclamation-triangle';
            case 'error':
                return 'fas fa-times-circle';
            case 'info':
            default:
                return 'fas fa-info-circle';
        }
    },

    getDelay(type) {
        switch (type) {
            case 'error':
                return 10000; // 10 seconds for errors
            case 'warning':
                return 7000;  // 7 seconds for warnings
            case 'success':
                return 3000;  // 3 seconds for success
            case 'info':
            default:
                return 5000;  // 5 seconds for info
        }
    },

    playSound(type) {
        // Only play sounds if the user has granted permission
        if (document.hidden && Notification.permission === 'granted') {
            const audio = new Audio();
            
            switch (type) {
                case 'error':
                    audio.src = '/static/sounds/error.mp3';
                    break;
                case 'warning':
                    audio.src = '/static/sounds/warning.mp3';
                    break;
                case 'success':
                    audio.src = '/static/sounds/success.mp3';
                    break;
                case 'info':
                    audio.src = '/static/sounds/info.mp3';
                    break;
            }

            audio.play().catch(() => {
                // Ignore audio play errors
            });
        }
    },

    success(message, title = 'Success') {
        return this.show(title, message, 'success');
    },

    error(message, title = 'Error') {
        return this.show(title, message, 'error');
    },

    warning(message, title = 'Warning') {
        return this.show(title, message, 'warning');
    },

    info(message, title = 'Info') {
        return this.show(title, message, 'info');
    }
};

// Initialize notifications when DOM is loaded
document.addEventListener('DOMContentLoaded', () => Notifications.init());

// Request notification permission
if ('Notification' in window) {
    Notification.requestPermission();
} 