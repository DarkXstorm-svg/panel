<?php
// db_setup.php
require_once 'config.php'; // Make sure config.php is correctly configured

$pdo = get_db_connection(); // Get PDO database connection

// Create users table
$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_owner INTEGER DEFAULT 0
)");
echo "Checked 'users' table.<br>";

// NEW: Add failed_login_attempts and last_failed_login_time to users table
try {
    $pdo->exec("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0");
    echo "Added 'failed_login_attempts' column to 'users' table.<br>";
} catch (PDOException $e) {
    if (strpos($e->getMessage(), 'duplicate column name') === false) {
        error_log("Error adding failed_login_attempts column: " . $e->getMessage());
        echo "Error adding 'failed_login_attempts' column: " . $e->getMessage() . "<br>";
    } else {
        echo "'failed_login_attempts' column already exists.<br>";
    }
}

try {
    $pdo->exec("ALTER TABLE users ADD COLUMN last_failed_login_time TEXT"); // YYYY-MM-DD HH:MM:SS
    echo "Added 'last_failed_login_time' column to 'users' table.<br>";
} catch (PDOException $e) {
    if (strpos($e->getMessage(), 'duplicate column name') === false) {
        error_log("Error adding last_failed_login_time column: " . $e->getMessage());
        echo "Error adding 'last_failed_login_time' column: " . $e->getMessage() . "<br>";
    } else {
        echo "'last_failed_login_time' column already exists.<br>";
    }
}

// Create devices table
$pdo->exec("CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    user_name TEXT NOT NULL,
    approved INTEGER DEFAULT 0,
    expiration_date TEXT, -- YYYY-MM-DD
    registration_date TEXT DEFAULT CURRENT_DATE
)");
echo "Checked 'devices' table.<br>";

// Create device_logs table for auditing device changes
$pdo->exec("CREATE TABLE IF NOT EXISTS device_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    action TEXT NOT NULL, -- e.g., 'approved', 'denied', 'expiration_set', 'deleted', 'registered'
    old_status TEXT,
    new_status TEXT,
    expiration_change TEXT, -- e.g., 'from YYYY-MM-DD to YYYY-MM-DD' or 'none to YYYY-MM-DD'
    action_by TEXT, -- username of the admin performing the action
    action_date TEXT DEFAULT CURRENT_TIMESTAMP
)");
echo "Checked 'device_logs' table.<br>";

// Create user_logs table for auditing admin actions
$pdo->exec("CREATE TABLE IF NOT EXISTS user_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL, -- e.g., 'added_admin', 'toggled_admin_status', 'deleted_user', 'reset_password'
    details TEXT,
    action_date TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)");
echo "Checked 'user_logs' table.<br>";

// Create settings table for global application settings
$pdo->exec("CREATE TABLE IF NOT EXISTS settings (
    setting_key TEXT PRIMARY KEY NOT NULL,
    setting_value TEXT
)");
echo "Checked 'settings' table.<br>";

// Create notifications table for in-app notifications
$pdo->exec("CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, -- NULL for global notifications, otherwise specific user
    message TEXT NOT NULL,
    type TEXT DEFAULT 'info', -- success, danger, warning, info, primary
    read_status INTEGER DEFAULT 0, -- 0 for unread, 1 for read
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)");
echo "Checked 'notifications' table.<br>";

// NEW: Create login_attempts table for logging login attempts (for brute-force monitoring)
$pdo->exec("CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    attempt_time TEXT DEFAULT CURRENT_TIMESTAMP,
    success INTEGER DEFAULT 0 -- 0 for failure, 1 for success
)");
echo "Created 'login_attempts' table.<br>";


// Add is_owner column if it doesn't exist (for existing databases)
try {
    $pdo->exec("ALTER TABLE users ADD COLUMN is_owner INTEGER DEFAULT 0");
    echo "Added 'is_owner' column to 'users' table.<br>";
} catch (PDOException $e) {
    if (strpos($e->getMessage(), 'duplicate column name') === false) {
        error_log("Error adding is_owner column: " . $e->getMessage());
        echo "Error adding 'is_owner' column: " . $e->getMessage() . "<br>";
    } else {
        echo "'is_owner' column already exists.<br>";
    }
}

// Add initial admin user if not exists and set as owner
$stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
$stmt->execute([':username' => ADMIN_USERNAME]);
if ($stmt->fetchColumn() == 0) {
    $password_hash = password_hash(ADMIN_PASSWORD, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, is_admin, is_owner) VALUES (:username, :password_hash, 1, 1)");
    $stmt->execute([
        ':username' => ADMIN_USERNAME,
        ':password_hash' => $password_hash
    ]);
    echo "Admin user '" . ADMIN_USERNAME . "' created successfully and set as owner.<br>";
} else {
    // If admin user already exists, ensure they are marked as owner
    $stmt = $pdo->prepare("SELECT is_owner FROM users WHERE username = :username");
    $stmt->execute([':username' => ADMIN_USERNAME]);
    if ($stmt->fetchColumn() == 0) {
        $stmt_update = $pdo->prepare("UPDATE users SET is_owner = 1 WHERE username = :username");
        $stmt_update->execute([':username' => ADMIN_USERNAME]);
        echo "Admin user '" . ADMIN_USERNAME . "' updated to owner.<br>";
    } else {
        echo "Admin user '" . ADMIN_USERNAME . "' already exists and is an owner.<br>";
    }
}

// Insert default settings if not exists
$default_settings = [
    'default_expiration_days' => '30',
    'site_name' => 'AshxDeath Panel',
    'max_login_attempts' => '5', // NEW: Max login attempts before temporary lockout
    'login_lockout_time_minutes' => '15', // NEW: Lockout duration in minutes
];
foreach ($default_settings as $key => $value) {
    $stmt = $pdo->prepare("INSERT OR IGNORE INTO settings (setting_key, setting_value) VALUES (:key, :value)");
    $stmt->execute([':key' => $key, ':value' => $value]);
}
echo "Default settings initialized.<br>";

echo "Database setup complete.";
?>