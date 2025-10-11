// Theme Management System
class ThemeManager {
    constructor() {
        this.init();
    }

    init() {
        this.loadSavedTheme();
        this.setupEventListeners();
        this.updateThemeIcon();
    }

    loadSavedTheme() {
        const savedTheme = localStorage.getItem('theme') || 'light';
        this.setTheme(savedTheme);
    }

    setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        this.updateThemeIcon();
        
        // Emit theme change event for other components
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
    }

    toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        this.setTheme(newTheme);
        
        // Add visual feedback
        this.showThemeChangeToast(newTheme);
    }

    updateThemeIcon() {
        const themeToggle = document.getElementById('themeToggle');
        const themeIcon = themeToggle?.querySelector('.theme-icon');
        const currentTheme = document.documentElement.getAttribute('data-theme');
        
        if (themeIcon) {
            if (currentTheme === 'dark') {
                themeIcon.className = 'fas fa-sun theme-icon';
                themeToggle.setAttribute('title', 'Switch to light mode');
            } else {
                themeIcon.className = 'fas fa-moon theme-icon';
                themeToggle.setAttribute('title', 'Switch to dark mode');
            }
        }
    }

    showThemeChangeToast(theme) {
        const toastHTML = `
            <div class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header">
                    <i class="fas fa-${theme === 'dark' ? 'moon' : 'sun'} me-2 text-primary"></i>
                    <strong class="me-auto">Theme Changed</strong>
                    <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body">
                    Switched to ${theme} mode
                </div>
            </div>
        `;
        
        const toastContainer = document.getElementById('toastContainer');
        if (toastContainer) {
            toastContainer.insertAdjacentHTML('beforeend', toastHTML);
            const toast = toastContainer.lastElementChild;
            const bsToast = new bootstrap.Toast(toast, { delay: 2000 });
            bsToast.show();
            
            // Remove toast element after it's hidden
            toast.addEventListener('hidden.bs.toast', () => toast.remove());
        }
    }

    setupEventListeners() {
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleTheme();
            });
        }

        // Listen for system theme changes
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', (e) => {
                // Only auto-switch if user hasn't manually set a preference
                if (!localStorage.getItem('theme')) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
        }
    }

    getCurrentTheme() {
        return document.documentElement.getAttribute('data-theme');
    }
}

// Initialize theme manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.themeManager = new ThemeManager();
});

// Navigation Active State Management
class NavigationManager {
    constructor() {
        this.init();
    }

    init() {
        this.setActiveNavItem();
    }

    setActiveNavItem() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.modern-nav-link[data-page]');
        
        navLinks.forEach(link => {
            link.classList.remove('active');
            
            const page = link.getAttribute('data-page');
            if ((currentPath === '/' || currentPath === '/dashboard') && page === 'dashboard') {
                link.classList.add('active');
            } else if (currentPath.includes(`/${page}`)) {
                link.classList.add('active');
            }
        });
    }
}

// Initialize navigation manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.navigationManager = new NavigationManager();
});

// Loading Overlay Management
class LoadingManager {
    constructor() {
        this.overlay = document.getElementById('loadingOverlay');
    }

    show(text = 'Loading...') {
        if (this.overlay) {
            const loadingText = this.overlay.querySelector('.loading-text');
            if (loadingText) {
                loadingText.textContent = text;
            }
            this.overlay.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    hide() {
        if (this.overlay) {
            this.overlay.style.display = 'none';
            document.body.style.overflow = '';
        }
    }
}

// Initialize loading manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.loadingManager = new LoadingManager();
});

// Confirmation Modal Management
class ConfirmationModal {
    constructor() {
        this.modal = document.getElementById('confirmationModal');
        this.confirmButton = document.getElementById('confirmButton');
        this.messageElement = document.getElementById('confirmationMessage');
        this.bsModal = null;
        this.init();
    }

    init() {
        if (this.modal) {
            this.bsModal = new bootstrap.Modal(this.modal);
        }
    }

    show(message, confirmCallback, options = {}) {
        if (!this.bsModal) return;

        // Set message
        if (this.messageElement) {
            this.messageElement.textContent = message;
        }

        // Set confirm button text and style
        if (this.confirmButton) {
            this.confirmButton.textContent = options.confirmText || 'Confirm';
            this.confirmButton.className = `btn ${options.confirmClass || 'btn-primary'}`;
        }

        // Set up confirm handler
        const handleConfirm = () => {
            this.bsModal.hide();
            if (confirmCallback) {
                confirmCallback();
            }
            this.confirmButton.removeEventListener('click', handleConfirm);
        };

        this.confirmButton.addEventListener('click', handleConfirm);

        // Show modal
        this.bsModal.show();
    }

    hide() {
        if (this.bsModal) {
            this.bsModal.hide();
        }
    }
}

// Initialize confirmation modal when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.confirmationModal = new ConfirmationModal();
});

// Utility Functions
window.showToast = function(message, type = 'info', title = null) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) return;

    const iconMap = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };

    const toastHTML = `
        <div class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header">
                <i class="fas fa-${iconMap[type] || 'info-circle'} me-2 text-${type}"></i>
                <strong class="me-auto">${title || type.charAt(0).toUpperCase() + type.slice(1)}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHTML);
    const toast = toastContainer.lastElementChild;
    const bsToast = new bootstrap.Toast(toast, { delay: 4000 });
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
};

window.showConfirmation = function(message, callback, options = {}) {
    if (window.confirmationModal) {
        window.confirmationModal.show(message, callback, options);
    }
};

// Auto-dismiss flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        });
    }, 5000);
});