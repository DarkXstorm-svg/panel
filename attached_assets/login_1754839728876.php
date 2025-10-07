<?php
session_start();
require_once 'config.php'; // Make sure config.php is correctly configured

// NEW: Set security headers at the very beginning
set_security_headers();

$pdo = get_db_connection(); // Get PDO database connection
$message = ''; // Initialize message variable

// NEW: Fetch login attempt settings from the database
$max_login_attempts = (int)get_setting($pdo, 'max_login_attempts', 5);
$login_lockout_time_minutes = (int)get_setting($pdo, 'login_lockout_time_minutes', 15);

// NEW: Display logout message if set
if (isset($_SESSION['logout_message'])) {
    $message = $_SESSION['logout_message'];
    // Use a specific class for logout messages for better styling or JS handling
    echo '<script>
            document.addEventListener("DOMContentLoaded", function() {
                showCustomToast("Logout", "' . htmlspecialchars($message) . '", "info");
            });
          </script>';
    unset($_SESSION['logout_message']); // Clear it after display
}

// If already logged in, redirect to index.php
if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
    header('Location: index.php');
    exit;
}

// Get client IP address (for logging login attempts)
$ip_address = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ip_address = $_SERVER['HTTP_CLIENT_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

// Handle Login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_submit'])) {
    $username_input = trim($_POST['username'] ?? ''); // Use a different variable name to avoid conflict with $user['username']
    $password = $_POST['password'] ?? '';

    // Fetch user details including failed login attempts
    $stmt = $pdo->prepare("SELECT id, username, password_hash, is_admin, is_owner, failed_login_attempts, last_failed_login_time FROM users WHERE username = :username");
    $stmt->execute([':username' => $username_input]);
    $user = $stmt->fetch();

    $login_success = false; // Flag to track if login was successful

    if ($user) {
        // Check for temporary lockout
        if ($user['failed_login_attempts'] >= $max_login_attempts) {
            $last_fail_timestamp = strtotime($user['last_failed_login_time']);
            $unlock_time = $last_fail_timestamp + ($login_lockout_time_minutes * 60);

            if (time() < $unlock_time) {
                $time_remaining = ceil(($unlock_time - time()) / 60);
                $message = "Too many failed login attempts. Please try again in {$time_remaining} minutes.";
                log_login_attempt($pdo, $username_input, $ip_address, false); // Log lockout attempt
                goto end_login_attempt; // Jump to end of login processing
            } else {
                // Lockout period has passed, reset attempts
                $stmt_reset = $pdo->prepare("UPDATE users SET failed_login_attempts = 0, last_failed_login_time = NULL WHERE id = :id");
                $stmt_reset->execute([':id' => $user['id']]);
                // Log this reset action if desired
            }
        }

        if (password_verify($password, $user['password_hash'])) {
            if ($user['is_admin']) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = true;
                $_SESSION['is_owner'] = $user['is_owner']; // Store is_owner status

                // NEW: Reset failed login attempts on successful login
                $stmt_reset = $pdo->prepare("UPDATE users SET failed_login_attempts = 0, last_failed_login_time = NULL WHERE id = :id");
                $stmt_reset->execute([':id' => $user['id']]);

                $login_success = true;
                log_login_attempt($pdo, $user['username'], $ip_address, true); // Log successful attempt
                header('Location: index.php');
                exit;
            } else {
                $message = "You do not have admin privileges.";
                log_login_attempt($pdo, $user['username'], $ip_address, false); // Log failed attempt (privilege)
            }
        } else {
            $message = "Invalid username or password.";
            // NEW: Increment failed login attempts
            $stmt_fail = $pdo->prepare("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_time = CURRENT_TIMESTAMP WHERE id = :id");
            $stmt_fail->execute([':id' => $user['id']]);
            log_login_attempt($pdo, $user['username'], $ip_address, false); // Log failed attempt (wrong password)
        }
    } else {
        $message = "Invalid username or password.";
        // Log attempt for non-existent user (username_input as no user found)
        log_login_attempt($pdo, $username_input, $ip_address, false);
    }
    end_login_attempt: // Label for goto statement
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #00BCD4; /* Cyan */
            --primary-hover: #00ACC1; /* Darker Cyan */
            --border-radius: 12px;
            --box-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --dark-color: #212529; /* Black/Dark Grey */
            --danger-color: #ef4444; /* Red */
            --success-color: #10b981; /* Green */
            --info-color: #0d6efd; /* Light Blue (Bootstrap info) */
            --warning-color: #f59e0b; /* Yellow/Orange */
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f1f5f9;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: white;
            padding: 40px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow-lg);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .login-container h2 {
            margin-bottom: 25px;
            color: var(--primary-color);
            font-weight: 700;
        }
        .login-container .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        .login-container label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--dark-color);
        }
        .login-container input[type="text"],
        .login-container input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #e2e8f0;
            border-radius: var(--border-radius);
            font-size: 1rem;
            box-sizing: border-box; /* Ensures padding doesn't increase width */
        }
        .login-container button {
            width: 100%;
            padding: 12px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            font-size: 1.1rem;
            font-weight: 600;
            transition: background-color 0.2s ease;
        }
        .login-container button:hover {
            background-color: var(--primary-hover);
        }
        .login-message {
            margin-top: 15px;
            color: var(--danger-color);
            font-weight: 500;
        }
        .dark-mode {
            background-color: #0f172a;
            color: #e2e8f0;
        }
        .dark-mode .login-container {
            background-color: #1e293b;
        }
        .dark-mode .login-container label,
        .dark-mode .login-container h2 {
            color: #e2e8f0;
        }
        .dark-mode .login-container input {
            background-color: #334155;
            color: #e2e8f0;
            border-color: #475569;
        }
         /* Added for toast */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1100;
        }

        .toast {
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow-lg);
            border: none;
        }

        .toast-header {
            background: var(--primary-color); /* Matches primary color */
            color: white;
            border-radius: var(--border-radius) var(--border-radius) 0 0;
        }
    </style>
</head>
<body>
    <div class="toast-container">
    </div>

    <div class="login-container">
        <h2>Admin Login</h2>
        <?php if ($message && !isset($_SESSION['logout_message'])): // Display only if it's not a logout message ?>
            <p class="login-message"><?php echo $message; ?></p>
        <?php endif; ?>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" name="login_submit">Login</button>
        </form>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Helper function to show a custom toast notification
        function showCustomToast(header, message, type = 'primary') {
            const toastContainer = document.querySelector('.toast-container');
            const toastHtml = `
                <div class="toast fade show" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="toast-header bg-${type} text-white">
                        <strong class="me-auto">${header}</strong>
                        <small>Just now</small>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                    <div class="toast-body">
                        ${message}
                    </div>
                </div>
            `;
            toastContainer.insertAdjacentHTML('beforeend', toastHtml);
            const newToastEl = toastContainer.lastElementChild;
            const newToast = new bootstrap.Toast(newToastEl, {
                autohide: true,
                delay: 5000
            });
            newToast.show();
            newToastEl.addEventListener('hidden.bs.toast', function () {
                newToastEl.remove();
            });
        }
    </script>
</body>
</html>