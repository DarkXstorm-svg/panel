// Dashboard JavaScript functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Load notifications on page load
    loadNotifications();

    // Auto-refresh notifications every 30 seconds
    setInterval(loadNotifications, 30000);

    // Handle notification click to mark as read
    document.addEventListener('click', function(e) {
        if (e.target.closest('.notification-item')) {
            const notificationItem = e.target.closest('.notification-item');
            const notificationId = notificationItem.dataset.notificationId;
            
            if (notificationId && notificationItem.classList.contains('unread')) {
                markNotificationAsRead(notificationId);
            }
        }
    });

    // Handle "Mark all as read" button
    const markAllReadBtn = document.getElementById('markAllReadBtn');
    if (markAllReadBtn) {
        markAllReadBtn.addEventListener('click', function() {
            markNotificationAsRead('all');
        });
    }
});

function loadNotifications() {
    // This would typically fetch notifications via AJAX
    // For now, we'll update the notification dropdown content
    updateNotificationDropdown();
}

function updateNotificationDropdown() {
    const notificationDropdown = document.querySelector('#notificationDropdown');
    const notificationList = document.querySelector('#notification-list');
    
    if (!notificationList) return;

    // This is a placeholder - in a real implementation, you'd fetch from the server
    // For now, we'll assume notifications are already loaded in the template
    const notifications = document.querySelectorAll('.notification-item');
    
    if (notifications.length === 0) {
        notificationList.innerHTML = `
            <div class="dropdown-item text-center text-muted">
                <i class="fas fa-bell-slash"></i> No notifications
            </div>
        `;
    }
}

function markNotificationAsRead(notificationId) {
    const formData = new FormData();
    formData.append('csrf_token', document.querySelector('input[name="csrf_token"]').value);
    formData.append('notification_id', notificationId);

    fetch('/mark_notification_read', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (notificationId === 'all') {
                document.querySelectorAll('.notification-item.unread').forEach(item => {
                    item.classList.remove('unread');
                });
                updateNotificationBadge(0);
            } else {
                const notificationItem = document.querySelector(`[data-notification-id="${notificationId}"]`);
                if (notificationItem) {
                    notificationItem.classList.remove('unread');
                }
                updateNotificationBadge();
            }
            showToast('Success', 'Notification(s) marked as read', 'success');
        }
    })
    .catch(error => {
        console.error('Error marking notification as read:', error);
        showToast('Error', 'Failed to mark notification as read', 'danger');
    });
}

function updateNotificationBadge(count) {
    const badge = document.querySelector('#notificationDropdown .badge');
    
    if (count !== undefined) {
        if (count > 0) {
            if (badge) {
                badge.textContent = count;
            } else {
                const newBadge = document.createElement('span');
                newBadge.className = 'badge bg-danger';
                newBadge.textContent = count;
                document.querySelector('#notificationDropdown').appendChild(newBadge);
            }
        } else if (badge) {
            badge.remove();
        }
    } else {
        // Recalculate count
        const unreadCount = document.querySelectorAll('.notification-item.unread').length;
        updateNotificationBadge(unreadCount);
    }
}

function showToast(title, message, type = 'primary') {
    const toastContainer = document.querySelector('.toast-container');
    const toastId = 'toast-' + Date.now();
    
    const toastHtml = `
        <div id="${toastId}" class="toast fade" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <strong class="me-auto">${title}</strong>
                <small>Just now</small>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    const newToastEl = document.getElementById(toastId);
    const newToast = new bootstrap.Toast(newToastEl, {
        autohide: true,
        delay: 5000
    });
    
    newToast.show();
    
    newToastEl.addEventListener('hidden.bs.toast', function() {
        newToastEl.remove();
    });
}

// Form validation helper
function validateForm(formElement) {
    const inputs = formElement.querySelectorAll('input[required], select[required], textarea[required]');
    let isValid = true;
    
    inputs.forEach(input => {
        if (!input.value.trim()) {
            input.classList.add('is-invalid');
            isValid = false;
        } else {
            input.classList.remove('is-invalid');
        }
    });
    
    return isValid;
}

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });
});

// Confirm dialogs for dangerous actions
document.addEventListener('click', function(e) {
    const button = e.target.closest('button[data-confirm], input[data-confirm]');
    if (button) {
        const confirmMessage = button.getAttribute('data-confirm');
        if (!confirm(confirmMessage)) {
            e.preventDefault();
            return false;
        }
    }
});

// Auto-refresh for real-time updates
let refreshInterval;

function startAutoRefresh(intervalMs = 60000) {
    refreshInterval = setInterval(() => {
        // Only refresh if user is active (not away from tab)
        if (!document.hidden) {
            loadNotifications();
            updateDashboardStats();
        }
    }, intervalMs);
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
}

function updateDashboardStats() {
    // This would fetch updated statistics via AJAX
    // For now, we'll skip this implementation as it requires backend changes
}

// Handle page visibility changes
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        stopAutoRefresh();
    } else {
        startAutoRefresh();
    }
});

// Start auto-refresh on dashboard pages
if (window.location.pathname === '/' || window.location.pathname.includes('dashboard')) {
    startAutoRefresh();
}
