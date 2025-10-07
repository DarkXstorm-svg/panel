<?php
// config.php
define('DB_PATH', __DIR__ . '/checker_data.sqlite'); // Path to your SQLite database file
define('ADMIN_USERNAME', 'ASH'); // Set your admin username
define('ADMIN_PASSWORD', 'Joshua091003@'); // Set your admin password (will be hashed on first run)

// Function to get a PDO database connection
function get_db_connection() {
    try {
        $pdo = new PDO('sqlite:' . DB_PATH);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection error: " . $e->getMessage());
        die("Database connection failed.");
    }
}

// Function to log device actions
function log_device_action($pdo, $deviceId, $action, $oldStatus, $newStatus, $expirationChange, $actionBy) {
    try {
        $stmt = $pdo->prepare("INSERT INTO device_logs (device_id, action, old_status, new_status, expiration_change, action_by) VALUES (:device_id, :action, :old_status, :new_status, :expiration_change, :action_by)");
        $stmt->execute([
            ':device_id' => $deviceId,
            ':action' => $action,
            ':old_status' => $oldStatus,
            ':new_status' => $newStatus,
            ':expiration_change' => $expirationChange,
            ':action_by' => $actionBy
        ]);
    } catch (PDOException $e) {
        // Log the error but don't stop execution, as logging is secondary
        error_log("Error logging device action: " . $e->getMessage());
    }
}

// Function to log user actions
function log_user_action($pdo, $userId, $username, $action, $details = '') {
    try {
        $stmt = $pdo->prepare("INSERT INTO user_logs (user_id, username, action, details) VALUES (:user_id, :username, :action, :details)");
        $stmt->execute([
            ':user_id' => $userId,
            ':username' => $username,
            ':action' => $action,
            ':details' => $details
        ]);
    } catch (PDOException $e) {
        error_log("Error logging user action: " . $e->getMessage());
    }
}

// Function to get a setting from the database
function get_setting($pdo, $setting_key, $default_value = null) {
    try {
        $stmt = $pdo->prepare("SELECT setting_value FROM settings WHERE setting_key = :setting_key");
        $stmt->execute([':setting_key' => $setting_key]);
        $result = $stmt->fetchColumn();
        return $result !== false ? $result : $default_value;
    } catch (PDOException $e) {
        error_log("Error getting setting '{$setting_key}': " . $e->getMessage());
        return $default_value;
    }
}

// Function to set a setting in the database
function set_setting($pdo, $setting_key, $setting_value) {
    try {
        $stmt = $pdo->prepare("INSERT OR REPLACE INTO settings (setting_key, setting_value) VALUES (:setting_key, :setting_value)");
        $stmt->execute([':setting_key' => $setting_key, ':setting_value' => $setting_value]);
        return true;
    } catch (PDOException $e) {
        error_log("Error setting setting '{$setting_key}': " . $e->getMessage());
        return false;
    }
}

// Function to add a notification
function add_notification($pdo, $user_id, $message, $type = 'info') {
    try {
        $stmt = $pdo->prepare("INSERT INTO notifications (user_id, message, type) VALUES (:user_id, :message, :type)");
        $stmt->execute([
            ':user_id' => $user_id,
            ':message' => $message,
            ':type' => $type
        ]);
    } catch (PDOException $e) {
        error_log("Error adding notification: " . $e->getMessage());
    }
}

// NEW: Function to log login attempts (success or failure)
function log_login_attempt($pdo, $username, $ip_address, $success) {
    try {
        $stmt = $pdo->prepare("INSERT INTO login_attempts (username, ip_address, success) VALUES (:username, :ip_address, :success)");
        $stmt->execute([
            ':username' => $username,
            ':ip_address' => $ip_address,
            ':success' => (int)$success // Cast to integer for DB
        ]);
    } catch (PDOException $e) {
        error_log("Error logging login attempt for {$username}: " . $e->getMessage());
    }
}

// NEW: Function to set common security headers
// It's generally better to do this in a central file or web server config.
// Call this function at the very beginning of your PHP scripts.
function set_security_headers() {
    // Prevent clickjacking
    header('X-Frame-Options: DENY');
    // Enable XSS protection
    header('X-XSS-Protection: 1; mode=block');
    // Prevent MIME-sniffing
    header('X-Content-Type-Options: nosniff');
    // Strict-Transport-Security (HSTS) - ONLY if you are exclusively on HTTPS
    // header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    // Content Security Policy (CSP) - Requires careful configuration, can break site if incorrect
    // header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://code.jquery.com; style-src 'self' https://cdn.jsdelivr.net;");
}

?>