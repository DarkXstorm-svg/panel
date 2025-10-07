<?php
session_start();
require_once 'config.php'; // Make sure config.php is correctly configured

// Set security headers at the very beginning
set_security_headers(); //

$pdo = get_db_connection(); // Get PDO database connection
$message = ''; // Initialize message variable
$is_logged_in = false; // Initialize flag
$is_admin = false; // Initialize flag
$is_owner = false; // Initialize flag
$username_display = ''; // Initialize variable
$devices = []; // Initialize array
$users = []; // Initialize array
$device_logs = []; // Initialize array for device logs
$user_logs = []; // Initialize array for user logs
$notifications = []; // Initialize array for notifications

// Fetch general settings from the database
$default_expiration_days = get_setting($pdo, 'default_expiration_days', 30); //
$site_name = get_setting($pdo, 'site_name', 'AshxDeath Panel'); //

// Generate CSRF token if not already set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// --- Check Session for Login Status and Roles ---
if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
    $is_logged_in = true;
    $is_admin = true;
    $username_display = $_SESSION['username'];
    if (isset($_SESSION['is_owner']) && $_SESSION['is_owner']) { // Check for is_owner in session
        $is_owner = true;
    }
    // Fetch notifications for the logged-in user and global notifications
    $stmt_notifs = $pdo->prepare("SELECT * FROM notifications WHERE user_id IS NULL OR user_id = :user_id ORDER BY created_at DESC LIMIT 10"); //
    $stmt_notifs->execute([':user_id' => $_SESSION['user_id']]); //
    $notifications = $stmt_notifs->fetchAll(); //

    // Get unread notification count
    $stmt_unread_notifs = $pdo->prepare("SELECT COUNT(*) FROM notifications WHERE read_status = 0 AND (user_id IS NULL OR user_id = :user_id)"); //
    $stmt_unread_notifs->execute([':user_id' => $_SESSION['user_id']]); //
    $unread_notification_count = $stmt_unread_notifs->fetchColumn(); //

} else {
    // If not logged in as admin, redirect to login page
    header('Location: login.php');
    exit;
}

// --- Handle all POST requests (including CSRF validation) ---
if ($is_logged_in && $_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF token for all POST requests
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $message = "Error: Invalid request. Please try again.";
        // Regenerate the token on failure as well
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        // Skip further processing for this request
    } else {
        // Regenerate token after successful validation to prevent "double submission" and enhance security
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

        // Handle marking notifications as read
        if (isset($_POST['mark_notification_read'])) { //
            $notification_id = $_POST['notification_id'] ?? null; //
            if ($notification_id) { //
                try { //
                    $stmt_mark_read = $pdo->prepare("UPDATE notifications SET read_status = 1 WHERE id = :id AND (user_id IS NULL OR user_id = :user_id)"); //
                    $stmt_mark_read->execute([':id' => $notification_id, ':user_id' => $_SESSION['user_id']]); //
                    // Message not needed here, AJAX will handle
                } catch (PDOException $e) { //
                    error_log("Error marking notification as read: " . $e->getMessage()); //
                }
            }
        }
        // Handle marking all notifications as read
        elseif (isset($_POST['mark_all_notifications_read'])) { //
            try { //
                $stmt_mark_all_read = $pdo->prepare("UPDATE notifications SET read_status = 1 WHERE user_id IS NULL OR user_id = :user_id"); //
                $stmt_mark_all_read->execute([':user_id' => $_SESSION['user_id']]); //
                // Message not needed here, AJAX will handle
            } catch (PDOException $e) { //
                error_log("Error marking all notifications as read: " . $e->getMessage()); //
            }
        }
        // Handle general settings update
        elseif (isset($_POST['update_settings_submit'])) { //
            $new_default_expiration_days = trim($_POST['default_expiration_days'] ?? ''); //
            $new_site_name = trim($_POST['site_name'] ?? ''); //

            if (!is_numeric($new_default_expiration_days) || $new_default_expiration_days < 1) { //
                $message = "Error: Default expiration days must be a positive number."; //
            } else {
                try { //
                    set_setting($pdo, 'default_expiration_days', $new_default_expiration_days); //
                    set_setting($pdo, 'site_name', $new_site_name); //
                    $message = "Settings updated successfully."; //
                    log_user_action($pdo, $_SESSION['user_id'], $_SESSION['username'], 'updated_settings', "Default exp: {$new_default_expiration_days}, Site name: {$new_site_name}"); //
                    add_notification($pdo, null, "Application settings updated by {$_SESSION['username']}.", 'primary'); // Global notification
                } catch (PDOException $e) { //
                    $message = "Error updating settings: " . $e->getMessage(); //
                }
            }
        }

        // Handle User Management Actions (only if logged in and owner)
        // IMPORTANT: Only an owner should be able to add/delete other admins or toggle admin status
        if ($is_owner) {
            // Handle adding a new admin user
            if (isset($_POST['add_admin_user_submit'])) {
                $new_admin_username = trim($_POST['new_admin_username'] ?? '');
                $new_admin_password = $_POST['new_admin_password'] ?? '';

                if (empty($new_admin_username) || empty($new_admin_password)) {
                    $message = "Error: Username and Password are required to add an admin user.";
                } else {
                    try {
                        // Check if username already exists
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = :username");
                        $stmt->execute([':username' => $new_admin_username]);
                        if ($stmt->fetchColumn() > 0) {
                            $message = "Error: Username '{$new_admin_username}' already exists.";
                        } else {
                            $password_hash = password_hash($new_admin_password, PASSWORD_DEFAULT);
                            // Ensure new users added here are 'admin' but not 'owner' by default
                            $stmt = $pdo->prepare("INSERT INTO users (username, password_hash, is_admin, is_owner) VALUES (:username, :password_hash, 1, 0)");
                            $stmt->execute([
                                ':username' => $new_admin_username,
                                ':password_hash' => $password_hash
                            ]);
                            $message = "Admin user '{$new_admin_username}' added successfully.";
                            log_user_action($pdo, $_SESSION['user_id'], $_SESSION['username'], 'added_admin', "Added new admin: {$new_admin_username}"); //
                            add_notification($pdo, null, "New admin user '{$new_admin_username}' added by {$_SESSION['username']}.", 'success'); //
                        }
                    } catch (PDOException $e) {
                        $message = "Error adding admin user: " . $e->getMessage();
                    }
                }
            }
            // Handle user permission/delete actions AND Password Reset
            elseif (isset($_POST['user_action'])) {
                $action = $_POST['user_action'] ?? '';
                $user_id_to_act = $_POST['user_id_to_act'] ?? '';

                if (!empty($user_id_to_act)) {
                    // Fetch target user's current data for logging and checks
                    $stmt_target_user = $pdo->prepare("SELECT username, is_admin, is_owner FROM users WHERE id = :id");
                    $stmt_target_user->execute([':id' => $user_id_to_act]);
                    $target_user_data = $stmt_target_user->fetch();

                    if (!$target_user_data) {
                        $message = "Error: Target user not found.";
                    } elseif ($user_id_to_act == $_SESSION['user_id'] && ($action === 'toggle_admin' || $action === 'delete_user')) {
                        $message = "Error: You cannot change your own admin status or delete your own account.";
                    } elseif ($action === 'toggle_admin') {
                        // Prevent a non-owner from toggling another owner's status (optional, but good practice)
                        if (!$is_owner && $target_user_data['is_owner']) {
                             $message = "Error: Only an owner can modify another owner's status.";
                        } else {
                            $new_admin_status = (1 - $target_user_data['is_admin']);
                            $stmt = $pdo->prepare("UPDATE users SET is_admin = :is_admin WHERE id = :id");
                            $stmt->execute([':is_admin' => $new_admin_status, ':id' => $user_id_to_act]);
                            $status_change = $new_admin_status == 1 ? 'Promoted to Admin' : 'Demoted from Admin';
                            $message = "User '{$target_user_data['username']}' status toggled successfully: {$status_change}.";
                            log_user_action($pdo, $_SESSION['user_id'], $_SESSION['username'], 'toggled_admin_status', "User: {$target_user_data['username']} (ID: {$user_id_to_act}) to {$status_change}"); //
                            add_notification($pdo, $user_id_to_act, "Your admin status was changed by {$_SESSION['username']} to '{$status_change}'.", 'warning'); //
                            add_notification($pdo, null, "Admin status for '{$target_user_data['username']}' toggled by {$_SESSION['username']}.", 'warning'); //
                        }
                    } elseif ($action === 'delete_user') {
                        // Prevent deleting the *last* owner (optional, but prevents locking out)
                        $stmt_check_owner_count = $pdo->prepare("SELECT COUNT(*) FROM users WHERE is_owner = 1");
                        $owner_count = $stmt_check_owner_count->fetchColumn();

                        if ($target_user_data['is_owner'] && $owner_count <= 1 && $user_id_to_act != $_SESSION['user_id']) {
                            $message = "Error: Cannot delete the last owner account.";
                        } elseif ($target_user_data['is_owner'] && $user_id_to_act == $_SESSION['user_id'] && $owner_count > 1) {
                             $message = "Error: You cannot delete your own owner account if there are other owners. Please have another owner delete your account if needed.";
                        } else {
                            $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
                            $stmt->execute([':id' => $user_id_to_act]);
                            $message = "User '{$target_user_data['username']}' deleted successfully.";
                            log_user_action($pdo, $_SESSION['user_id'], $_SESSION['username'], 'deleted_user', "Deleted user: {$target_user_data['username']} (ID: {$user_id_to_act})"); //
                            add_notification($pdo, null, "User '{$target_user_data['username']}' deleted by {$_SESSION['username']}.", 'danger'); //
                        }
                    } elseif ($action === 'reset_password') { // Admin-initiated password reset
                        $new_password = $_POST['new_password'] ?? ''; //
                        if (empty($new_password)) { //
                            $message = "Error: New password cannot be empty."; //
                        } else {
                            $password_hash = password_hash($new_password, PASSWORD_DEFAULT); //
                            $stmt = $pdo->prepare("UPDATE users SET password_hash = :password_hash WHERE id = :id"); //
                            $stmt->execute([':password_hash' => $password_hash, ':id' => $user_id_to_act]); //
                            $message = "Password for user '{$target_user_data['username']}' reset successfully."; //
                            log_user_action($pdo, $_SESSION['user_id'], $_SESSION['username'], 'reset_password', "Reset password for user: {$target_user_data['username']} (ID: {$user_id_to_act})"); //
                            add_notification($pdo, $user_id_to_act, "Your password was reset by {$_SESSION['username']}.", 'warning'); //
                            add_notification($pdo, null, "Password for '{$target_user_data['username']}' reset by {$_SESSION['username']}.", 'warning'); //
                        }
                    }
                    if (isset($_SERVER['HTTP_HX_REQUEST'])) {
                        // If it's an HTMX request, just echo message and exit
                        echo "<div class='alert alert-success' role='alert'>{$message}</div>";
                        exit;
                    }
                }
            }
        }

        // Device actions (accessible by all admins and owners)
        // Ensure these actions are processed only if not already handled by user management
        if (!isset($_POST['add_admin_user_submit']) && !isset($_POST['user_action']) && !isset($_POST['update_settings_submit']) && !isset($_POST['mark_notification_read']) && !isset($_POST['mark_all_notifications_read'])) {
            if (isset($_POST['device_action'])) {
                $action = $_POST['device_action'] ?? '';
                $device_id_to_act = trim($_POST['device_id_to_act'] ?? '');
                $expiration_days = $_POST['expiration_days'] ?? null;

                if (!empty($device_id_to_act)) {
                    try {
                        // Fetch current device status before action for logging
                        $current_device_status_text = 'N/A';
                        $current_expiration_date = 'N/A';
                        $stmt_fetch_current = $pdo->prepare("SELECT approved, expiration_date FROM devices WHERE device_id = :device_id");
                        $stmt_fetch_current->execute([':device_id' => $device_id_to_act]);
                        $current_device_data = $stmt_fetch_current->fetch();
                        if ($current_device_data) {
                            $current_device_status_text = ($current_device_data['approved'] == 1) ? 'Approved' : 'Pending';
                            if ($current_device_data['approved'] == 1 && $current_device_data['expiration_date'] && strtotime($current_device_data['expiration_date']) < time()) {
                                $current_device_status_text = 'Expired';
                            }
                            $current_expiration_date = $current_device_data['expiration_date'] ?? 'N/A';
                        }

                        if ($action === 'approve') {
                            $expiration_date = null;
                            if ($expiration_days !== null && is_numeric($expiration_days) && $expiration_days > 0) {
                                $expiration_date = date('Y-m-d', strtotime("+$expiration_days days"));
                            }
                            $stmt = $pdo->prepare("UPDATE devices SET approved = 1, expiration_date = :expiration_date WHERE device_id = :device_id");
                            $stmt->execute([':expiration_date' => $expiration_date, ':device_id' => $device_id_to_act]);
                            $message = "Device '{$device_id_to_act}' approved" . ($expiration_date ? " until {$expiration_date}" : "") . ".";
                            log_device_action($pdo, $device_id_to_act, 'approved', $current_device_status_text, 'Approved', "{$current_expiration_date} to {$expiration_date}", $_SESSION['username']);
                            add_notification($pdo, null, "Device '{$device_id_to_act}' approved by {$_SESSION['username']}.", 'success'); //
                        } elseif ($action === 'deny') {
                            $stmt = $pdo->prepare("UPDATE devices SET approved = 0, expiration_date = NULL WHERE device_id = :device_id");
                            $stmt->execute([':device_id' => $device_id_to_act]);
                            $message = "Device '{$device_id_to_act}' denied.";
                            log_device_action($pdo, $device_id_to_act, 'denied', $current_device_status_text, 'Denied', "{$current_expiration_date} to NULL", $_SESSION['username']);
                            add_notification($pdo, null, "Device '{$device_id_to_act}' denied by {$_SESSION['username']}.", 'danger'); //
                        } elseif ($action === 'set_expiration') {
                            $expiration_date = null;
                            if ($expiration_days !== null && is_numeric($expiration_days) && $expiration_days > 0) {
                                $expiration_date = date('Y-m-d', strtotime("+$expiration_days days"));
                            }
                            $stmt = $pdo->prepare("UPDATE devices SET expiration_date = :expiration_date WHERE device_id = :device_id");
                            $stmt->execute([':expiration_date' => $expiration_date, ':device_id' => $device_id_to_act]);
                            $message = "Expiration for '{$device_id_to_act}' set to " . ($expiration_date ? $expiration_date : "None") . ".";
                            log_device_action($pdo, $device_id_to_act, 'expiration_set', $current_device_status_text, $current_device_status_text, "{$current_expiration_date} to {$expiration_date}", $_SESSION['username']);
                            add_notification($pdo, null, "Expiration for '{$device_id_to_act}' set by {$_SESSION['username']}.", 'info'); //
                        } elseif ($action === 'delete') {
                            $stmt = $pdo->prepare("DELETE FROM devices WHERE device_id = :device_id");
                            $stmt->execute([':device_id' => $device_id_to_act]);
                            $message = "Device '{$device_id_to_act}' deleted successfully.";
                            log_device_action($pdo, $device_id_to_act, 'deleted', $current_device_status_text, 'Deleted', 'N/A', $_SESSION['username']);
                            add_notification($pdo, null, "Device '{$device_id_to_act}' deleted by {$_SESSION['username']}.", 'secondary'); //
                        }
                    } catch (PDOException $e) {
                        $message = "Error: " . $e->getMessage();
                    }
                }
            } elseif (isset($_POST['add_device_submit'])) { // Existing logic for adding devices
                $new_device_id = trim($_POST['new_device_id'] ?? '');
                $new_user_name = trim($_POST['new_user_name'] ?? '');
                $initial_expiration_days = $_POST['initial_expiration_days'] ?? null;

                if (empty($new_device_id) || empty($new_user_name)) {
                    $message = "Error: Device ID and User Name are required to add a device.";
                } else {
                    try {
                        // Check if device_id already exists
                        $stmt = $pdo->prepare("SELECT COUNT(*) FROM devices WHERE device_id = :device_id");
                        $stmt->execute([':device_id' => $new_device_id]);
                        if ($stmt->fetchColumn() > 0) {
                            $message = "Error: Device ID '{$new_device_id}' already exists.";
                        } else {
                            $initial_expiration_date = null;
                            if ($initial_expiration_days !== null && is_numeric($initial_expiration_days) && $initial_expiration_days > 0) {
                                $initial_expiration_date = date('Y-m-d', strtotime("+$initial_expiration_days days"));
                            }
                            $stmt = $pdo->prepare("INSERT INTO devices (device_id, user_name, approved, expiration_date, registration_date) VALUES (:device_id, :user_name, 1, :expiration_date, CURRENT_DATE)");
                            $stmt->execute([
                                ':device_id' => $new_device_id,
                                ':user_name' => $new_user_name,
                                ':expiration_date' => $initial_expiration_date
                            ]);
                            $message = "Device '{$new_device_id}' for user '{$new_user_name}' added and approved" . ($initial_expiration_date ? " until {$initial_expiration_date}" : "") . ".";
                            log_device_action($pdo, $new_device_id, 'registered_and_approved', 'N/A', 'Approved', "N/A to {$initial_expiration_date}", $_SESSION['username']);
                            add_notification($pdo, null, "New device '{$new_device_id}' added and approved by {$_SESSION['username']}.", 'success'); //
                        }
                    } catch (PDOException $e) {
                        $message = "Error adding device: " . $e->getMessage();
                    }
                }
            }
        }
    }
}


// --- Fetch Devices and Users (always if logged in as admin) ---
if ($is_logged_in) {
    $devices = $pdo->query("SELECT * FROM devices ORDER BY approved ASC, registration_date DESC")->fetchAll();
    // Fetch is_owner status for user management
    $users = $pdo->query("SELECT id, username, is_admin, is_owner FROM users ORDER BY username ASC")->fetchAll();
    // Fetch recent device logs for transactions (expanded for full history)
    $device_logs_full = $pdo->query("SELECT * FROM device_logs ORDER BY action_date DESC")->fetchAll(); //
    // Fetch recent user logs
    $user_logs = $pdo->query("SELECT * FROM user_logs ORDER BY action_date DESC LIMIT 10")->fetchAll(); //


    // Calculate statistics for dashboard cards
    $total_devices = count($devices);
    $approved_devices = count(array_filter($devices, function($d) { return $d['approved'] == 1 && (!$d['expiration_date'] || strtotime($d['expiration_date']) >= time()); }));
    $pending_devices = count(array_filter($devices, function($d) { return $d['approved'] == 0; }));
    $expired_devices = count(array_filter($devices, function($d) { return $d['approved'] == 1 && $d['expiration_date'] && strtotime($d['expiration_date']) < time(); }));

} else {
    // This block should ideally not be reached if the header redirect works
    header('Location: login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?php echo htmlspecialchars($site_name); ?> | Advanced Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="https://via.placeholder.com/32" type="image/png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.css" rel="stylesheet">
    <link href="https://cdn.datatables.net/1.13.4/css/dataTables.bootstrap5.min.css" rel="stylesheet">
    <style>
        /* Your existing CSS styles */
        :root {
            --primary-color: #00BCD4; /* Cyan */
            --primary-hover: #00ACC1; /* Darker Cyan */
            --secondary-color: #6c757d; /* Bootstrap secondary */
            --success-color: #28a745; /* Green */
            --info-color: #0dcaf0; /* Light Blue */
            --warning-color: #ffc107; /* Yellow/Orange */
            --danger-color: #dc3545; /* Red */
            --dark-color: #212529; /* Black/Dark Grey */
            --light-color: #f8f9fa; /* White/Light Grey */
            --sidebar-width: 280px;
            --sidebar-collapsed-width: 80px;
            --transition-speed: 0.3s;
            --border-radius: 12px;
            --box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --box-shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --gradient-primary: linear-gradient(135deg, var(--primary-color) 0%, #0097A7 100%); /* Cyan gradient */
            --owner-color: #673AB7; /* Deep Purple for Owner badge */
            --purple-color: #800080; /* Custom Purple for Expired logs */
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--light-color); /* Lighter background */
            transition: all var(--transition-speed) ease;
            overflow-x: hidden;
            color: var(--dark-color);
        }

        /* Navbar */
        .navbar {
            box-shadow: var(--box-shadow);
            background-color: white;
            padding: 0.75rem 1rem;
        }

        .navbar-brand {
            font-weight: 700;
            letter-spacing: 0.5px;
            color: var(--dark-color);
        }

        .notification-badge {
            position: absolute;
            top: 0;
            right: 0;
            transform: translate(25%, -25%);
            font-size: 0.6rem;
            padding: 0.25em 0.4em;
        }

        /* Sidebar */
        .sidebar {
            height: 100vh;
            position: fixed;
            background-color: white;
            color: var(--dark-color);
            transition: all var(--transition-speed) ease;
            z-index: 1000;
            box-shadow: var(--box-shadow);
            border-right: 1px solid #e2e8f0;
            /* Default state for mobile: hidden */
            transform: translateX(-100%);
            left: 0;
        }

        /* Show sidebar on small screens when 'show' class is added */
        .sidebar.show {
            transform: translateX(0);
        }

        /* Default state for desktop: expanded */
        @media (min-width: 992px) {
            .sidebar {
                width: var(--sidebar-width);
                transform: translateX(0); /* Always visible on desktop */
            }

            .sidebar-collapsed {
                width: var(--sidebar-collapsed-width);
                overflow: hidden;
            }

            .sidebar-expanded {
                width: var(--sidebar-width);
            }

            .main-content {
                margin-left: var(--sidebar-width);
            }
            .main-content-expanded { /* For collapsed sidebar on desktop */
                margin-left: var(--sidebar-collapsed-width);
            }
        }

        /* Control visibility of toggle buttons based on screen size */
        .sidebar-toggle { /* Hamburger icon */
            display: block; /* Default visible on mobile */
        }
        .sidebar-minimizer { /* Chevron icon */
            display: none; /* Default hidden on mobile */
        }

        @media (min-width: 992px) {
            .sidebar-toggle {
                display: none !important; /* Hide hamburger on desktop */
            }
            .sidebar-minimizer {
                display: block !important; /* Show chevron on desktop */
            }
        }


        .sidebar .nav-link {
            color: var(--secondary-color);
            border-radius: var(--border-radius);
            margin: 0.25rem 0.75rem;
            padding: 0.75rem 1rem;
            transition: all 0.2s;
            white-space: nowrap;
            font-weight: 500;
            display: flex;
            align-items: center;
        }

        .sidebar .nav-link:hover {
            color: var(--primary-color);
            background-color: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
            transform: translateX(5px);
        }

        .sidebar .nav-link.active {
            color: white;
            background: var(--gradient-primary);
            font-weight: 600;
            box-shadow: 0 4px 6px -1px rgba(0, 188, 212, 0.3), 0 2px 4px -1px rgba(0, 188, 212, 0.2);
        }

        .sidebar .nav-link i {
            min-width: 24px;
            text-align: center;
            margin-right: 12px;
            transition: margin var(--transition-speed) ease;
            font-size: 1.1rem;
        }

        .sidebar-collapsed .nav-link i {
            margin-right: 0;
            font-size: 1.2rem;
        }

        .sidebar-collapsed .nav-link span {
            display: none;
        }

        .sidebar-collapsed .brand-text,
        .sidebar-collapsed .sidebar-footer {
            display: none;
        }

        /* Cards */
        .card {
            border: none;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            margin-bottom: 1.5rem;
            background-color: white;
            overflow: hidden;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--box-shadow-lg);
        }

        .card-header {
            border-bottom: 1px solid #e2e8f0;
            background-color: transparent;
            font-weight: 600;
            padding: 1rem 1.5rem;
            background-color: white;
        }

        .card-body {
            padding: 1.5rem;
        }

        /* Profile */
        .profile-img {
            width: 100px;
            height: 100px;
            object-fit: cover;
            border: 3px solid white;
            box-shadow: var(--box-shadow);
            border-radius: 50%;
        }

        /* Dark Mode */
        .dark-mode {
            background-color: #1a202c; /* Darker background */
            color: #e2e8f0; /* Light text */
        }

        .dark-mode .navbar,
        .dark-mode .card {
            background-color: #2d3748; /* Darker card/navbar */
            color: #e2e8f0;
            border-color: #4a5568;
        }

        .dark-mode .card-header {
            border-bottom: 1px solid #4a5568;
            background-color: #2d3748;
        }

        .dark-mode .form-control,
        .dark-mode .form-select {
            background-color: #4a5568;
            color: #e2e8f0;
            border-color: #64748b;
        }

        .dark-mode .breadcrumb {
            background-color: #4a5568;
        }

        .dark-mode .breadcrumb-item a {
            color: #cbd5e1;
        }

        .dark-mode .sidebar {
            background-color: #2d3748;
            border-right-color: #4a5568;
        }

        .dark-mode .sidebar .nav-link {
            color: #a0aec0;
        }

        .dark-mode .sidebar .nav-link:hover {
            color: var(--primary-color);
            background-color: rgba(0, 188, 212, 0.2); /* Cyan with opacity */
        }

        .dark-mode .sidebar .nav-link.active {
            color: white;
        }

        /* Custom Text */
        .text-Hex {
            color: var(--primary-color);
            font-weight: 700;
        }

        /* Progress Bars */
        .progress {
            height: 8px;
            border-radius: 4px;
            background-color: #e2e8f0;
        }

        .dark-mode .progress {
            background-color: #4a5568;
        }

        /* Stats Cards */
        .stat-card {
            border-left: 4px solid;
            border-radius: var(--border-radius);
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 100px;
            height: 100px;
            background: radial-gradient(circle, rgba(255, 255, 255, 0.1) 0%, rgba(255, 255, 255, 0) 70%);
            border-radius: 50%;
            transform: translate(30%, -30%);
        }

        .stat-card.primary {
            border-left-color: var(--primary-color);
        }

        .stat-card.success {
            border-left-color: var(--success-color);
        }

        .stat-card.warning {
            border-left-color: var(--warning-color);
        }

        .stat-card.danger {
            border-left-color: var(--danger-color);
        }

        .stat-card .icon-shape {
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
        }

        .stat-card.primary .icon-shape {
            background-color: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
            color: var(--primary-color);
        }

        .stat-card.success .icon-shape {
            background-color: rgba(40, 167, 69, 0.1); /* Green with opacity */
            color: var(--success-color);
        }

        .stat-card.warning .icon-shape {
            background-color: rgba(255, 193, 7, 0.1); /* Yellow with opacity */
            color: var(--warning-color);
        }

        .stat-card.danger .icon-shape {
            background-color: rgba(220, 53, 69, 0.1); /* Red with opacity */
            color: var(--danger-color);
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f5f9;
        }

        ::-webkit-scrollbar-thumb {
            background: #cbd5e1;
            border-radius: 10px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #94a3b8;
        }

        .dark-mode ::-webkit-scrollbar-track {
            background: #2d3748;
        }

        .dark-mode ::-webkit-scrollbar-thumb {
            background: #4a5568;
        }

        .dark-mode ::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }

        /* Animations */
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        /* Custom Tabs */
        .custom-tabs .nav-link {
            border: none;
            color: var(--secondary-color);
            font-weight: 500;
            padding: 0.75rem 1.25rem;
            position: relative;
        }

        .custom-tabs .nav-link.active {
            color: var(--primary-color);
            background-color: transparent;
        }

        .custom-tabs .nav-link.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 40%;
            height: 3px;
            background: var(--gradient-primary);
            border-radius: 3px;
        }

        .dark-mode .custom-tabs .nav-link {
            color: #a0aec0;
        }

        .dark-mode .custom-tabs .nav-link.active {
            color: var(--primary-color);
        }

        /* Toast Notification */
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

        /* Task List */
        .task-list .task-item {
            padding: 0.75rem 1rem;
            border-left: 3px solid transparent;
            transition: all 0.3s;
            border-radius: var(--border-radius);
            margin-bottom: 0.5rem;
            background-color: white;
        }

        .task-list .task-item:hover {
            background-color: rgba(0, 188, 212, 0.05); /* Cyan with opacity */
            border-left-color: var(--primary-color);
        }

        .dark-mode .task-list .task-item {
            background-color: #2d3748;
        }

        .dark-mode .task-list .task-item:hover {
            background-color: rgba(0, 188, 212, 0.2); /* Cyan with opacity */
        }

        /* Activity Timeline */
        .timeline {
            position: relative;
            padding-left: 30px;
        }

        .timeline:before {
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background-color: #e2e8f0;
        }

        .dark-mode .timeline:before {
            background-color: #4a5568;
        }

        .timeline-item {
            position: relative;
            padding-bottom: 1.5rem;
        }

        .timeline-item:last-child {
            padding-bottom: 0;
        }

        .timeline-item:before {
            content: '';
            position: absolute;
            left: -30px;
            top: 5px;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: var(--gradient-primary);
            border: 3px solid white;
            z-index: 1;
        }

        .dark-mode .timeline-item:before {
            border-color: #2d3748;
        }

        /* Custom Switch */
        .custom-switch .form-check-input {
            width: 44px;
            height: 24px;
        }

        .custom-switch .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        /* Avatar */
        .avatar {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid white;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .avatar-group {
            display: flex;
        }

        .avatar-group .avatar {
            margin-right: -10px;
            border: 2px solid white;
        }

        /* Status Indicator */
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 5px;
        }

        .status-online {
            background-color: var(--success-color);
        }

        .status-offline {
            background-color: var(--secondary-color);
        }

        .status-busy {
            background-color: var(--danger-color);
        }

        .status-away {
            background-color: var(--warning-color);
        }

        /* Badges */
        .badge {
            font-weight: 500;
            padding: 0.35em 0.65em;
            font-size: 0.75em;
        }

        /* Buttons */
        .btn {
            border-radius: var(--border-radius);
            font-weight: 500;
            padding: 0.5rem 1rem;
            transition: all 0.2s;
        }

        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-primary:hover {
            background-color: var(--primary-hover);
            border-color: var(--primary-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 188, 212, 0.3), 0 2px 4px -1px rgba(0, 188, 212, 0.2);
        }

        .btn-outline-primary {
            color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .btn-outline-primary:hover {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        /* Tables */
        .table {
            color: inherit;
        }

        .table-hover tbody tr:hover {
            background-color: rgba(0, 188, 212, 0.05); /* Cyan with opacity */
        }

        .dark-mode .table-hover tbody tr:hover {
            background-color: rgba(0, 188, 212, 0.2); /* Cyan with opacity */
        }

        /* Dropdowns */
        .dropdown-menu {
            border: none;
            box-shadow: var(--box-shadow-lg);
            border-radius: var(--border-radius);
            padding: 0.5rem;
        }

        .dropdown-item {
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-weight: 500;
            transition: all 0.2s;
        }

        .dropdown-item:hover {
            background-color: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
            color: var(--primary-color);
        }

        /* Forms */
        .form-control,
        .form-select {
            border-radius: var(--border-radius);
            padding: 0.5rem 1rem;
            border: 1px solid #e2e8f0;
        }

        .form-control:focus,
        .form-select:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(0, 188, 212, 0.25); /* Cyan with opacity */
        }

        /* Accordion */
        .accordion {
            --bs-accordion-border-color: #e2e8f0;
            --bs-accordion-btn-focus-border-color: var(--primary-color);
            --bs-accordion-btn-focus-box-shadow: 0 0 0 0.25rem rgba(0, 188, 212, 0.25); /* Cyan with opacity */
            --bs-accordion-active-color: var(--primary-color);
            --bs-accordion-active-bg: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
        }

        .accordion-button {
            font-weight: 500;
        }

        /* Modal */
        .modal-content {
            border-radius: var(--border-radius);
            border: none;
            box-shadow: var(--box-shadow-lg);
        }

        /* FullCalendar */
        .fc {
            --fc-border-color: #e2e8f0;
            --fc-today-bg-color: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
            --fc-page-bg-color: white;
            --fc-neutral-bg-color: white;
        }

        .fc .fc-button {
            background-color: white;
            border-color: #e2e8f0;
            color: #334155;
            text-transform: capitalize;
            font-weight: 500;
            border-radius: var(--border-radius);
            padding: 0.4rem 0.8rem;
        }

        .fc .fc-button-primary:not(:disabled).fc-button-active {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            color: white;
        }

        .fc .fc-button-primary:not(:disabled):hover {
            background-color: var(--primary-hover);
            border-color: var(--primary-hover);
            color: white;
        }

        .fc-event {
            border-radius: 6px;
            border: none;
            padding: 0.25rem 0.5rem;
            font-size: 0.85rem;
            background-color: var(--primary-color);
        }

        .fc-event:hover {
            opacity: 0.9;
        }

        .dark-mode .fc {
            --fc-border-color: #4a5568;
            --fc-today-bg-color: rgba(0, 188, 212, 0.2); /* Cyan with opacity */
            --fc-page-bg-color: #2d3748;
            --fc-neutral-bg-color: #2d3748;
        }

        .dark-mode .fc .fc-button {
            background-color: #2d3748;
            border-color: #4a5568;
            color: #e2e8f0;
        }

        .dark-mode .fc-event {
            background-color: var(--primary-color);
        }

        /* DataTables */
        .dataTables_wrapper .dataTables_length select,
        .dataTables_wrapper .dataTables_filter input {
            border-radius: var(--border-radius);
            padding: 0.25rem 0.5rem;
            border: 1px solid #e2e8f0;
        }

        .dataTables_wrapper .dataTables_paginate .paginate_button {
            border-radius: var(--border-radius);
            padding: 0.25rem 0.75rem;
            margin: 0 0.15rem;
            border: 1px solid #e2e8f0;
        }

        .dataTables_wrapper .dataTables_paginate .paginate_button.current {
            background: var(--gradient-primary);
            color: white !important;
            border: none;
        }

        .dark-mode .dataTables_wrapper .dataTables_length select,
        .dark-mode .dataTables_wrapper .dataTables_filter input {
            background-color: #4a5568;
            border-color: #64748b;
            color: #e2e8f0;
        }

        .dark-mode .dataTables_wrapper .dataTables_paginate .paginate_button {
            background-color: #2d3748;
            border-color: #4a5568;
            color: #e2e8f0 !important;
        }

        /* Kanban Board */
        .kanban-board {
            display: flex;
            overflow-x: auto;
            padding-bottom: 1rem;
            gap: 1rem;
        }

        .kanban-column {
            min-width: 280px;
            background-color: white;
            border-radius: var(--border-radius);
            padding: 1rem;
            box-shadow: var(--box-shadow);
        }

        .dark-mode .kanban-column {
            background-color: #2d3748;
        }

        .kanban-column-header {
            font-weight: 600;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #e2e8f0;
        }

        .dark-mode .kanban-column-header {
            border-bottom-color: #4a5568;
        }

        .kanban-item {
            background-color: white;
            border-radius: var(--border-radius);
            padding: 0.75rem 1rem;
            margin-bottom: 0.75rem;
            box-shadow: var(--box-shadow);
            cursor: grab;
            transition: all 0.2s;
        }

        .kanban-item:hover {
            transform: translateY(-2px);
            box-shadow: var(--box-shadow-lg);
        }

        .dark-mode .kanban-item {
            background-color: #2d3748;
        }

        /* File Manager */
        .file-item {
            border-radius: var(--border-radius);
            padding: 1rem;
            text-align: center;
            transition: all 0.2s;
        }

        .file-item:hover {
            background-color: rgba(0, 188, 212, 0.1); /* Cyan with opacity */
            transform: translateY(-2px);
        }

        .file-icon {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: var(--primary-color);
        }

        /* Chat Widget */
        .chat-container {
            height: 400px;
            display: flex;
            flex-direction: column;
        }

        .chat-messages {
            flex: 1;
            overflow-y: auto;
            padding: 1rem;
        }

        .chat-message {
            margin-bottom: 1rem;
            max-width: 80%;
        }

        .chat-message-incoming {
            align-self: flex-start;
            background-color: #e2e8f0;
            border-radius: 0 var(--border-radius) var(--border-radius) var(--border-radius);
            padding: 0.75rem 1rem;
        }

        .dark-mode .chat-message-incoming {
            background-color: #4a5568;
        }

        .chat-message-outgoing {
            align-self: flex-end;
            background: var(--gradient-primary);
            color: white;
            border-radius: var(--border-radius) 0 var(--border-radius) var(--border-radius);
            padding: 0.75rem 1rem;
        }

        .chat-input {
            border-top: 1px solid #e2e8f0;
            padding: 1rem;
        }

        .dark-mode .chat-input {
            border-top-color: #4a5568;
        }

        /* Pricing Cards */
        .pricing-card {
            border-radius: var(--border-radius);
            transition: all 0.3s;
            overflow: hidden;
        }

        .pricing-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--box-shadow-lg);
        }

        .pricing-card .card-header {
            padding: 1.5rem;
            text-align: center;
            background: var(--gradient-primary);
            color: white;
        }

        .pricing-card.featured .card-header {
            background: var(--gradient-primary);
        }

        .pricing-card .list-group-item {
            padding: 0.75rem 1.5rem;
            border-color: #e2e8f0;
        }

        .dark-mode .pricing-card .list-group-item {
            border-color: #4a5568;
            background-color: #2d3748;
        }

        /* Gradient Text */
        .gradient-text {
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        /* Loading Spinner */
        .spinner {
            width: 3rem;
            height: 3rem;
            border: 0.25em solid rgba(0, 188, 212, 0.2); /* Cyan with opacity */
            border-right-color: var(--primary-color);
            animation: spinner 0.75s linear infinite;
            border-radius: 50%;
        }

        @keyframes spinner {
            to {
                transform: rotate(360deg);
            }
        }

        /* Tooltips */
        .tooltip {
            --bs-tooltip-bg: var(--primary-color);
        }

        /* Popovers */
        .popover {
            border: none;
            box-shadow: var(--box-shadow-lg);
            border-radius: var(--border-radius);
        }

        .bs-popover-auto[data-popper-placement^=top]>.popover-arrow::after,
        .bs-popover-top>.popover-arrow::after {
            border-top-color: var(--primary-color);
        }

        /* Custom Checkbox */
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        /* Custom Radio */
        .form-check-input[type="radio"]:checked {
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='-4 -4 8 8'%3e%3ccircle r='2' fill='%23fff'/%3e%3csvg%3e");
        }

        /* Custom Range */
        .form-range::-webkit-slider-thumb {
            background: var(--gradient-primary);
        }

        .form-range::-moz-range-thumb {
            background: var(--gradient-primary);
        }

        /* Custom Select */
        .form-select {
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3e%3cpath fill='none' stroke='%236c757d' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M2 5l6 6 6-6'/%3e%3csvg%3e"); /* Secondary color for arrow */
            background-repeat: no-repeat;
            background-position: right 0.75rem center;
            background-size: 16px 12px;
        }

        .dark-mode .form-select {
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3e%3cpath fill='none' stroke='%23a0aec0' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M2 5l6 6 6-6'/%3e%3csvg%3e"); /* Light grey for arrow in dark mode */
        }

        /* Custom File Input */
        .form-file-button {
            background-color: var(--primary-color);
            color: white;
        }

        .form-file-button:hover {
            background-color: var(--primary-hover);
        }

        /* Custom Toggle */
        .toggle {
            position: relative;
            display: inline-block;
            width: 50px;
            height: 24px;
        }

        .toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #e2e8f0;
            transition: .4s;
            border-radius: 24px;
        }

        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }

        input:checked+.toggle-slider {
            background: var(--gradient-primary);
        }

        input:checked+.toggle-slider:before {
            transform: translateX(26px);
        }

        /* Custom Input Group */
        .input-group-text {
            background-color: #f1f5f9;
            border-color: #e2e8f0;
        }

        .dark-mode .input-group-text {
            background-color: #4a5568;
            border-color: #64748b;
        }

        /* Custom Breadcrumb */
        .breadcrumb {
            background-color: #f1f5f9;
            border-radius: var(--border-radius);
            padding: 0.75rem 1rem;
        }

        .breadcrumb-item a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
        }

        /* Custom Alert */
        .alert {
            border-radius: var(--border-radius);
            border: none;
        }

        /* Custom Pagination */
        .pagination .page-link {
            border-radius: var(--border-radius);
            margin: 0 0.25rem;
            color: var(--primary-color);
            border: none;
        }

        .pagination .page-item.active .page-link {
            background: var(--gradient-primary);
            color: white;
            border: none;
        }

        /* Custom Badge */
        .badge-primary {
            background: var(--gradient-primary);
        }

        /* Custom List Group */
        .list-group-item {
            border-color: #e2e8f0;
            padding: 0.75rem 1.25rem;
        }

        .dark-mode .list-group-item {
            background-color: #2d3748;
            border-color: #4a5568;
        }

        /* Custom Nav Tabs */
        .nav-tabs {
            border-bottom: 1px solid #e2e8f0;
        }

        .nav-tabs .nav-link {
            border: none;
            color: #6c757d; /* Secondary color */
            font-weight: 500;
            padding: 0.75rem 1.25rem;
            position: relative;
        }

        .nav-tabs .nav-link.active {
            color: var(--primary-color);
        }

        .nav-tabs .nav-link.active::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 0;
            width: 100%;
            height: 2px;
            background: var(--gradient-primary);
        }

        .dark-mode .nav-tabs {
            border-bottom-color: #4a5568;
        }

        .dark-mode .nav-tabs .nav-link {
            color: #a0aec0;
        }

        .dark-mode .nav-tabs .nav-link.active {
            color: var(--primary-color);
        }

        /* Custom Nav Pills */
        .nav-pills .nav-link.active {
            background: var(--gradient-primary);
        }

        /* Custom Modal */
        .modal-content {
            border-radius: var(--border-radius);
            border: none;
            box-shadow: var(--box-shadow-lg);
        }

        /* Custom Close Button */
        .btn-close-white {
            filter: invert(1);
        }

        /* Custom Toast */
        .toast {
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow-lg);
            border: none;
        }

        .toast-header {
            background: var(--gradient-primary);
            color: white;
            border-radius: var(--border-radius) var(--border-radius) 0 0;
        }

        /* Custom Toolbar */
        .toolbar {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        /* Custom Code Block */
        .code-block {
            background-color: #f8f9fa;
            border-radius: var(--border-radius);
            padding: 1rem;
            font-family: 'Courier New', Courier, monospace;
            overflow-x: auto;
        }

        .dark-mode .code-block {
            background-color: #2d3748;
        }

        /* Custom Divider */
        .divider {
            display: flex;
            align-items: center;
            text-align: center;
            color: #6c757d;
            margin: 1rem 0;
        }

        .divider::before,
        .divider::after {
            content: "";
            flex: 1;
            border-bottom: 1px solid #e2e8f0;
        }

        .divider::before {
            margin-right: 1rem;
        }

        .divider::after {
            margin-left: 1rem;
        }

        .dark-mode .divider {
            color: #a0aec0;
        }

        .dark-mode .divider::before,
        .dark-mode .divider::after {
            border-bottom-color: #4a5568;
        }

        /* Custom Empty State */
        .empty-state {
            text-align: center;
            padding: 2rem;
            color: #6c757d;
        }

        .empty-state-icon {
            font-size: 3rem;
            color: #cbd5e1;
            margin-bottom: 1rem;
        }

        .dark-mode .empty-state {
            color: #a0aec0;
        }

        .dark-mode .empty-state-icon {
            color: #4a5568;
        }

        /* Custom Floating Action Button */
        .fab {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 56px;
            height: 56px;
            border-radius: 50%;
            background: var(--gradient-primary);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--box-shadow-lg);
            z-index: 1000;
            cursor: pointer;
            transition: all 0.2s;
        }

        .fab:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px -3px rgba(0, 188, 212, 0.3); /* Cyan with opacity */
        }

        /* Custom Back to Top Button */
        .back-to-top {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: white;
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--box-shadow);
            z-index: 1000;
            cursor: pointer;
            transition: all 0.2s;
        }

        .back-to-top:hover {
            background-color: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }

        .dark-mode .back-to-top {
            background-color: #2d3748;
            color: var(--primary-color);
        }

        .dark-mode .back-to-top:hover {
            background-color: var(--primary-color);
            color: white;
        }

        /* Custom Notification Dot */
        .notification-dot {
            position: absolute;
            top: 0;
            right: 0;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--danger-color);
            border: 2px solid white;
        }

        .dark-mode .notification-dot {
            border-color: #2d3748;
        }

        /* Custom Ribbon */
        .ribbon {
            position: absolute;
            top: 0;
            right: 0;
            width: 150px;
            height: 150px;
            overflow: hidden;
        }

        .ribbon-content {
            position: absolute;
            display: block;
            width: 225px;
            padding: 15px 0;
            background-color: var(--primary-color);
            box-shadow: 0 5px 10px rgba(0, 0, 0, 0.1);
            color: white;
            font-size: 0.75rem;
            text-align: center;
            text-transform: uppercase;
            font-weight: 600;
            transform: rotate(45deg);
            right: -25px;
            top: 45px;
        }

        /* Custom Highlight */
        .highlight {
            background-color: rgba(255, 235, 59, 0.3);
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
        }

        /* Custom Pulse Animation */
        @keyframes pulse {
            0% {
                transform: scale(1);
            }

            50% {
                transform: scale(1.05);
            }

            100% {
                transform: scale(1);
            }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        /* Custom Shimmer Effect */
        .shimmer {
            background: linear-gradient(90deg, #f1f5f9 25%, #e2e8f0 50%, #f1f5f9 75%);
            background-size: 200% 100%;
            animation: shimmer 1.5s infinite;
            border-radius: var(--border-radius);
        }

        @keyframes shimmer {
            0% {
                background-position: 200% 0;
            }

            100% {
                background-position: -200% 0;
            }
        }

        .dark-mode .shimmer {
            background: linear-gradient(90deg, #2d3748 25%, #4a5568 50%, #2d3748 75%);
        }

        /* Custom Gradient Background */
        .gradient-bg {
            background: var(--gradient-primary);
            color: white;
        }

        /* Custom Glass Effect */
        .glass {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .dark-mode .glass {
            background: rgba(45, 55, 72, 0.7);
            border-color: rgba(255, 255, 255, 0.1);
        }

        /* Custom Text Truncation */
        .text-truncate-2 {
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        /* Custom Aspect Ratio */
        .aspect-ratio-16-9 {
            aspect-ratio: 16 / 9;
        }

        /* Custom Grid */
        .grid {
            display: grid;
            gap: 1rem;
        }

        .grid-cols-2 {
            grid-template-columns: repeat(2, 1fr);
        }

        @media (min-width: 768px) {
            .grid-cols-md-3 {
                grid-template-columns: repeat(3, 1fr);
            }
        }

        /* Custom Transition */
        .transition-all {
            transition: all 0.2s ease;
        }

        /* Custom Transform */
        .hover-scale:hover {
            transform: scale(1.02);
        }

        /* Custom Filter */
        .filter-grayscale {
            filter: grayscale(100%);
        }

        .hover-filter-grayscale:hover {
            filter: grayscale(0%);
        }

        /* Custom Blend Mode */
        .blend-multiply {
            mix-blend-mode: multiply;
        }

        /* Custom Clip Path */
        .clip-path-circle {
            clip-path: circle(50% at 50% 50%);
        }

        /* Custom Scroll Snap */
        .scroll-snap-x {
            scroll-snap-type: x mandatory;
        }

        .scroll-snap-align-start {
            scroll-snap-align: start;
        }

        /* Custom Sticky */
        .sticky-top {
            position: sticky;
            top: 0;
            z-index: 1020;
        }

        /* Custom Z-Index */
        .z-10 {
            z-index: 10;
        }

        /* Custom Opacity */
        .opacity-75 {
            opacity: 0.75;
        }

        /* Custom Cursor */
        .cursor-pointer {
            cursor: pointer;
        }

        /* Custom User Select */
        .user-select-none {
            user-select: none;
        }

        /* Custom Overflow */
        .overflow-hidden {
            overflow: hidden;
        }

        /* Custom Position */
        .position-relative {
            position: relative;
        }

        /* Custom Display */
        .display-inline-flex {
            display: inline-flex;
        }

        /* Custom Flex */
        .flex-center {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        /* Custom Text Decoration */
        .underline-offset-4 {
            text-underline-offset: 4px;
        }

        /* Custom Word Break */
        .break-words {
            word-break: break-word;
        }

        /* Custom Line Clamp */
        .line-clamp-3 {
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        /* Custom List Style */
        .list-style-none {
            list-style: none;
        }

        /* Custom Object Fit */
        .object-cover {
            object-fit: cover;
        }

        /* Custom Object Position */
        .object-center {
            object-position: center;
        }

        /* Custom Pointer Events */
        .pointer-events-none {
            pointer-events: none;
        }

        /* Custom Resize */
        .resize-none {
            resize: none;
        }

        /* Custom Scroll Behavior */
        .scroll-smooth {
            scroll-behavior: smooth;
        }

        /* Custom Text Overflow */
        .text-ellipsis {
            text-overflow: ellipsis;
        }

        /* Custom Whitespace */
        .whitespace-nowrap {
            white-space: nowrap;
        }

        /* Custom Word Spacing */
        .word-spacing-wide {
            word-spacing: 0.25em;
        }

        /* Custom Writing Mode */
        .writing-mode-vertical {
            writing-mode: vertical-rl;
        }

        /* Custom Isolation */
        .isolation-isolate {
            isolation: isolate;
        }

        /* Custom Backdrop Filter */
        .backdrop-blur-sm {
            backdrop-filter: blur(4px);
        }

        /* Custom Mix Blend Mode */
        .mix-blend-multiply {
            mix-blend-mode: multiply;
        }

        /* Custom Background Blend Mode */
        .bg-blend-multiply {
            background-blend-mode: multiply;
        }

        /* Custom Filter */
        .filter-drop-shadow {
            filter: drop-shadow(0 4px 6px rgba(0, 0, 0, 0.1));
        }

        /* Custom Backface Visibility */
        .backface-visible {
            backface-visibility: visible;
        }

        /* Custom Transform Style */
        .transform-style-preserve-3d {
            transform-style: preserve-3d;
        }

        /* Custom Transform Origin */
        .origin-center {
            transform-origin: center;
        }

        /* Custom Perspective */
        .perspective-1000 {
            perspective: 1000px;
        }

        /* Custom Transform */
        .rotate-45 {
            transform: rotate(45deg);
        }

        /* Custom Scale */
        .scale-110 {
            transform: scale(1.1);
        }

        /* Custom Translate */
        .translate-y-2 {
            transform: translateY(0.5rem);
        }

        /* Custom Skew */
        .skew-x-12 {
            transform: skewX(12deg);
        }

        /* Custom Transition Property */
        .transition-colors {
            transition-property: background-color, border-color, color, fill, stroke;
        }

        /* Custom Transition Duration */
        .duration-300 {
            transition-duration: 300ms;
        }

        /* Custom Transition Timing Function */
        .ease-in-out {
            transition-timing-function: ease-in-out;
        }

        /* Custom Animation */
        .animate-bounce {
            animation: bounce 1s infinite;
        }

        @keyframes bounce {

            0%,
            100% {
                transform: translateY(-25%);
                animation-timing-function: cubic-bezier(0.8, 0, 1, 1);
            }

            50% {
                transform: translateY(0);
                animation-timing-function: cubic-bezier(0, 0, 0.2, 1);
            }
        }

        /* Custom Will Change */
        .will-change-transform {
            will-change: transform;
        }

        /* Custom Content */
        .content-empty {
            content: "";
        }

        /* Custom Fill */
        .fill-current {
            fill: currentColor;
        }

        /* Custom Stroke */
        .stroke-current {
            stroke: currentColor;
        }

        /* Custom Stroke Width */
        .stroke-2 {
            stroke-width: 2;
        }

        /* Admin Panel Specific Styles */
        .status-pending { color: orange; font-weight: bold; }
        .status-approved { color: var(--success-color); font-weight: bold; }
        .status-denied { color: var(--danger-color); font-weight: bold; }
        .status-expired { color: var(--purple-color); /* Updated to use CSS variable */ font-weight: bold; }
        .device-actions form, .user-actions form { display: inline-block; margin-right: 5px; }
        .device-actions button, .user-actions button { padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; color: white; }
        .approve-btn { background-color: var(--success-color); }
        .deny-btn { background-color: var(--danger-color); }
        .expiration-input { width: 60px; }
        .set-exp-btn { background-color: var(--info-color); } /* Light Blue */
        .delete-btn { background-color: var(--secondary-color); } /* Secondary color */
        .toggle-admin-btn { background-color: var(--warning-color); color: black; } /* Warning color */
        .owner-badge { background-color: var(--owner-color); } /* Deep Purple for owner */
        .reset-password-btn { background-color: #6c757d; } /* Bootstrap secondary */

        /* New Dashboard Design Elements */
        .dashboard-header {
            background: linear-gradient(90deg, var(--primary-color) 0%, var(--info-color) 100%); /* Cyan to Light Blue gradient */
            color: white;
            padding: 3rem 2rem;
            border-radius: var(--border-radius);
            margin-bottom: 2rem;
            box-shadow: var(--box-shadow-lg);
            position: relative;
            overflow: hidden;
        }
        .dashboard-header::before {
            content: '';
            position: absolute;
            top: -50px;
            left: -50px;
            width: 200px;
            height: 200px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            transform: rotate(45deg);
        }
        .dashboard-header::after {
            content: '';
            position: absolute;
            bottom: -30px;
            right: -30px;
            width: 150px;
            height: 150px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
        }

        .dashboard-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card-modern {
            background-color: white;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            padding: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
            border-bottom: 5px solid;
        }

        .stat-card-modern:hover {
            transform: translateY(-8px);
            box-shadow: var(--box-shadow-lg);
        }

        .stat-card-modern .icon {
            font-size: 2.5rem;
            opacity: 0.2;
            position: absolute;
            top: 15px;
            right: 15px;
        }

        .stat-card-modern.primary-card { border-color: var(--primary-color); }
        .stat-card-modern.success-card { border-color: var(--success-color); }
        .stat-card-modern.warning-card { border-color: var(--warning-color); }
        .stat-card-modern.danger-card { border-color: var(--danger-color); }

        .stat-card-modern .value {
            font-size: 2.2rem;
            font-weight: 700;
            color: var(--dark-color);
            line-height: 1;
        }
        .stat-card-modern .label {
            font-size: 0.9rem;
            color: var(--secondary-color);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .stat-card-modern .change {
            font-size: 0.85rem;
            margin-top: 0.5rem;
        }
        .stat-card-modern .change.positive { color: var(--success-color); }
        .stat-card-modern .change.negative { color: var(--danger-color); }

        .dark-mode .stat-card-modern {
            background-color: #2d3748;
            color: #e2e8f0;
        }
        .dark-mode .stat-card-modern .value {
            color: #e2e8f0;
        }
        .dark-mode .stat-card-modern .label {
            color: #a0aec0;
        }

    </style>
</head>

<body>
    <div class="toast-container">
        </div>

    <nav class="navbar navbar-expand navbar-white bg-white shadow-sm">
        <div class="container-fluid">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link sidebar-toggle d-lg-none" href="#" role="button">
                        <i class="fas fa-bars"></i>
                    </a>
                </li>
                <li class="nav-item d-none d-sm-inline-block">
                    <a href="#" class="nav-link" id="homeNavLink">Home</a>
                </li>
                <li class="nav-item d-none d-sm-inline-block">
                    <a href="#" class="nav-link" id="contactNavLink">Contact</a>
                </li>
            </ul>

            <form class="d-flex mx-3" id="navbarSearchForm">
                <div class="input-group">
                    <input class="form-control" type="search" placeholder="Search" aria-label="Search" id="navbarSearchInput">
                    <button class="btn btn-outline-secondary" type="submit" id="navbarSearchBtn">
                        <i class="fas fa-search"></i>
                    </button>
                </div>
            </form>

            <ul class="navbar-nav ms-auto">
                <li class="nav-item dropdown">
                    <a class="nav-link position-relative" href="#" id="notificationsDropdown" role="button"
                        data-bs-toggle="dropdown" aria-expanded="false">
                        <i class="far fa-bell"></i>
                        <?php if ($unread_notification_count > 0): ?>
                            <span class="badge bg-warning notification-badge"><?php echo $unread_notification_count; ?></span>
                        <?php endif; ?>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end dropdown-notifications p-0"
                        aria-labelledby="notificationsDropdown">
                        <li class="dropdown-header bg-light py-2">
                            <div class="d-flex justify-content-between align-items-center">
                                <span><?php echo $unread_notification_count; ?> New Notifications</span>
                                <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" id="markAllNotificationsReadBtn">Mark all as read</button>
                            </div>
                        </li>
                        <li>
                            <hr class="dropdown-divider m-0">
                        </li>
                        <?php if (empty($notifications)): ?>
                            <li><span class="dropdown-item text-muted text-center">No notifications.</span></li>
                        <?php else: ?>
                            <?php foreach ($notifications as $notification): ?>
                                <li class="<?php echo ($notification['read_status'] == 0) ? 'fw-bold' : ''; ?>">
                                    <a class="dropdown-item notification-item d-flex align-items-center" href="#" data-notification-id="<?php echo $notification['id']; ?>">
                                        <div class="me-2 text-<?php echo htmlspecialchars($notification['type']); ?>">
                                            <?php
                                                $icon_class = 'fas fa-info-circle';
                                                if ($notification['type'] == 'success') $icon_class = 'fas fa-check-circle';
                                                elseif ($notification['type'] == 'danger') $icon_class = 'fas fa-exclamation-triangle';
                                                elseif ($notification['type'] == 'warning') $icon_class = 'fas fa-exclamation';
                                                elseif ($notification['type'] == 'primary') $icon_class = 'fas fa-star';
                                            ?>
                                            <i class="<?php echo $icon_class; ?> fa-lg"></i>
                                        </div>
                                        <div>
                                            <h6 class="mb-0 text-truncate" style="max-width: 250px;"><?php echo htmlspecialchars($notification['message']); ?></h6>
                                            <small class="text-muted"><?php echo htmlspecialchars(date('M d, H:i', strtotime($notification['created_at']))); ?></small>
                                        </div>
                                    </a>
                                </li>
                                <li><hr class="dropdown-divider m-0"></li>
                            <?php endforeach; ?>
                        <?php endif; ?>
                        <li class="dropdown-footer text-center py-2">
                            <a href="#notificationHistorySection" class="text-decoration-none" id="viewAllNotifications">View all notifications</a>
                        </li>
                    </ul>
                </li>
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button"
                        data-bs-toggle="dropdown" aria-expanded="false">
                        <img src="https://via.placeholder.com/30" alt="User" class="rounded-circle me-1" width="30" height="30">
                        <span class="d-none d-md-inline"><?php echo htmlspecialchars($username_display); ?></span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                        <li><a class="dropdown-item" href="#" id="userProfileLink"><i class="fas fa-user me-2"></i> Profile</a></li>
                        <li><a class="dropdown-item" href="#settingsSection" id="userSettingsLink"><i class="fas fa-cog me-2"></i> Settings</a></li>
                        <li>
                            <hr class="dropdown-divider">
                        </li>
                        <li><a class="dropdown-item" href="logout.php" id="userLogoutLink"><i class="fas fa-sign-out-alt me-2"></i> Logout</a></li>
                    </ul>
                </li>

                <li class="nav-item">
                    <div class="nav-link">
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" id="darkModeSwitch">
                            <label class="form-check-label" for="darkModeSwitch"><i class="fas fa-moon"></i></label>
                        </div>
                    </div>
                </li>
            </ul>
        </div>
    </nav>

    <div class="sidebar"> <div class="brand-container d-flex align-items-center justify-content-between py-3 px-3">
            <a href="#" class="d-flex align-items-center text-decoration-none">
                <img src="https://via.placeholder.com/40" alt="Logo" class="rounded-circle me-2" width="40" height="40">
                <span class="brand-text fs-4 fw-bold text-dark">Ash<span class="text-Hex">Hex</span></span>
            </a>
            <button class="btn btn-link text-dark sidebar-minimizer d-none d-lg-block">
                <i class="fas fa-chevron-left"></i>
            </button>
        </div>
        <hr class="sidebar-divider mx-3">

        <div class="user-panel d-flex align-items-center pb-3 mb-3 px-3">
            <div class="image me-3">
                <img src="https://via.placeholder.com/50" class="rounded-circle" alt="User Image" width="50" height="50">
            </div>
            <div class="info">
                <div class="d-flex align-items-center">
                    <span class="fw-bold"><?php echo htmlspecialchars($username_display); ?></span>
                    <span class="status-indicator status-online ms-2"></span>
                </div>
                <small class="text-muted">
                    <?php
                    if ($is_owner) {
                        echo "Owner";
                    } elseif ($is_admin) {
                        echo "Administrator";
                    } else {
                        echo "User"; // Fallback, though current logic redirects non-admins
                    }
                    ?>
                </small>
            </div>
        </div>
        <hr class="sidebar-divider mx-3">

        <div class="sidebar-search pb-3 px-3">
            <div class="input-group">
                <input class="form-control" type="search" placeholder="Search..." aria-label="Search" id="sidebarSearchInput">
                <button class="btn btn-outline-secondary" type="button" id="sidebarSearchBtn">
                    <i class="fas fa-search"></i>
                </button>
            </div>
        </div>
        <hr class="sidebar-divider mx-3">

        <ul class="nav nav-pills flex-column mb-auto px-2">
            <li class="nav-item">
                <a href="index.php" class="nav-link active" id="dashboardNavLink">
                    <i class="fas fa-tachometer-alt me-2"></i>
                    <span>Dashboard</span>
                </a>
            </li>

            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="collapse" href="#deviceManagementMenu" role="button" id="deviceManagementMenuToggle">
                    <i class="fas fa-mobile-alt me-2"></i>
                    <span>Device Management</span>
                    <i class="fas fa-angle-down ms-auto"></i>
                </a>
                <div class="collapse" id="deviceManagementMenu">
                    <ul class="nav flex-column ps-4">
                        <li class="nav-item">
                            <a href="#addDeviceSection" class="nav-link" id="addDeviceNavLink">
                                <i class="fas fa-plus-circle me-2"></i>
                                <span>Add Device</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#deviceTableSection" class="nav-link" id="listDevicesNavLink">
                                <i class="fas fa-list me-2"></i>
                                <span>List Devices</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#deviceActivityLogSection" class="nav-link" id="deviceActivityLogNavLink">
                                <i class="fas fa-history me-2"></i>
                                <span>Activity Log</span>
                            </a>
                        </li>
                    </ul>
                </div>
            </li>

            <?php if ($is_owner): // Only show user management for owners ?>
            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="collapse" href="#usersMenu" role="button" id="usersMenuToggle">
                    <i class="fas fa-users me-2"></i>
                    <span>User Management</span>
                    <i class="fas fa-angle-down ms-auto"></i>
                </a>
                <div class="collapse" id="usersMenu">
                    <ul class="nav flex-column ps-4">
                        <li class="nav-item">
                            <a href="#addAdminUserSection" class="nav-link" id="addAdminUserNavLink">
                                <i class="fas fa-user-plus me-2"></i>
                                <span>Add Admin User</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#adminUserListSection" class="nav-link" id="adminUserListNavLink">
                                <i class="fas fa-list me-2"></i>
                                <span>Admin User List</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#adminActivityLogSection" class="nav-link" id="adminActivityLogNavLink">
                                <i class="fas fa-user-clock me-2"></i>
                                <span>Admin Activity Log</span>
                            </a>
                        </li>
                    </ul>
                </div>
            </li>
            <?php endif; ?>

            <li class="nav-item">
                <a class="nav-link" data-bs-toggle="collapse" href="#settingsMenu" role="button" id="settingsMenuToggle">
                    <i class="fas fa-cogs me-2"></i>
                    <span>Settings</span>
                    <i class="fas fa-angle-down ms-auto"></i>
                </a>
                <div class="collapse" id="settingsMenu">
                    <ul class="nav flex-column ps-4">
                        <li class="nav-item">
                            <a href="#settingsSection" class="nav-link" id="generalSettingsNavLink">
                                <i class="fas fa-cog me-2"></i>
                                <span>General Settings</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#notificationHistorySection" class="nav-link" id="notificationsHistoryNavLink">
                                <i class="fas fa-bell me-2"></i>
                                <span>Notification History</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#" class="nav-link" id="securityNavLink">
                                <i class="fas fa-lock me-2"></i>
                                <span>Security</span>
                            </a>
                        </li>
                    </ul>
                </div>
            </li>

            <li class="nav-item">
                <a href="#" class="nav-link" id="analyticsNavLink">
                    <i class="fas fa-chart-line me-2"></i>
                    <span>Analytics</span>
                </a>
            </li>

            <li class="nav-item">
                <a href="#" class="nav-link" id="reportsNavLink">
                    <i class="fas fa-file-alt me-2"></i>
                    <span>Reports</span>
                </a>
            </li>

            <li class="nav-item">
                <a href="#" class="nav-link" id="calendarNavLink">
                    <i class="fas fa-calendar me-2"></i>
                    <span>Calendar</span>
                </a>
            </li>
        </ul>

        <hr class="sidebar-divider mx-3">

        <div class="sidebar-footer d-flex justify-content-between align-items-center px-3 py-2">
            <small class="text-muted">Version 2.0.0</small>
            <button class="btn btn-sm btn-outline-dark" id="toggleDarkMode">
                <i class="fas fa-moon"></i>
            </button>
        </div>
    </div>

    <div class="main-content">
        <div class="dashboard-header">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1 class="display-4 fw-bold mb-0">Welcome, <?php echo htmlspecialchars($username_display); ?>!</h1>
                    <p class="lead mt-2 mb-0 opacity-75">Overview of your device subscriptions and user management.</p>
                </div>
                <div class="col-md-4 text-md-end mt-3 mt-md-0">
                    <nav aria-label="breadcrumb" class="d-inline-block">
                        <ol class="breadcrumb bg-transparent mb-0">
                            <li class="breadcrumb-item"><a href="#" id="breadcrumbHome" class="text-white text-decoration-none"><i class="fas fa-home"></i> Home</a></li>
                            <li class="breadcrumb-item active text-white" aria-current="page">Dashboard</li>
                        </ol>
                    </nav>
                </div>
            </div>
        </div>

        <div class="dashboard-stats-grid">
            <div class="stat-card-modern primary-card" data-aos="fade-up" data-aos-delay="100">
                <div>
                    <div class="value"><?php echo $total_devices; ?></div>
                    <div class="label">Total Devices</div>
                    <div class="change positive"><i class="fas fa-arrow-up"></i> 12.5%</div>
                </div>
                <i class="fas fa-mobile-alt icon text-primary"></i>
            </div>

            <div class="stat-card-modern success-card" data-aos="fade-up" data-aos-delay="200">
                <div>
                    <div class="value"><?php echo $approved_devices; ?></div>
                    <div class="label">Approved Devices</div>
                    <div class="change positive"><i class="fas fa-arrow-up"></i> 8.3%</div>
                </div>
                <i class="fas fa-check-circle icon text-success"></i>
            </div>

            <div class="stat-card-modern warning-card" data-aos="fade-up" data-aos-delay="300">
                <div>
                    <div class="value"><?php echo $pending_devices; ?></div>
                    <div class="label">Pending Devices</div>
                    <div class="change negative"><i class="fas fa-arrow-down"></i> 2.4%</div>
                </div>
                <i class="fas fa-hourglass-half icon text-warning"></i>
            </div>

            <div class="stat-card-modern danger-card" data-aos="fade-up" data-aos-delay="400">
                <div>
                    <div class="value"><?php echo $expired_devices; ?></div>
                    <div class="label">Expired Devices</div>
                    <div class="change positive"><i class="fas fa-arrow-up"></i> 5.7%</div>
                </div>
                <i class="fas fa-calendar-times icon text-danger"></i>
            </div>
        </div>

        <div class="row" id="addDeviceSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Add New Device</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message && (strpos($message, 'Device') === 0) && strpos($message, 'Error') === false): /* Show success message for adding device */?>
                            <div class="alert alert-success"><?php echo $message; ?></div>
                        <?php elseif ($message && (strpos($message, 'Device ID') === 0 && strpos($message, 'exists') !== false)): ?>
                             <div class="alert alert-warning"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <div class="row g-3">
                                <div class="col-md-4">
                                    <label for="new_device_id" class="form-label">Device ID</label>
                                    <input type="text" class="form-control" id="new_device_id" name="new_device_id" placeholder="Enter Device ID" required>
                                </div>
                                <div class="col-md-4">
                                    <label for="new_user_name" class="form-label">User Name</label>
                                    <input type="text" class="form-control" id="new_user_name" name="new_user_name" placeholder="Enter User Name" required>
                                </div>
                                <div class="col-md-2">
                                    <label for="initial_expiration_days" class="form-label">Expiration (Days)</label>
                                    <input type="number" class="form-control" id="initial_expiration_days" name="initial_expiration_days" value="<?php echo htmlspecialchars($default_expiration_days); ?>" min="1" placeholder="<?php echo htmlspecialchars($default_expiration_days); ?>">
                                </div>
                                <div class="col-md-2 d-flex align-items-end">
                                    <button type="submit" name="add_device_submit" class="btn btn-primary w-100"><i class="fas fa-plus-circle me-2"></i>Add Device</button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row" id="deviceTableSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Device Management</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message && strpos($message, 'Device') === 0 && strpos($message, 'Error') === false && strpos($message, 'added') === false): ?>
                            <div class="alert alert-info"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <?php if ($message && strpos($message, 'Invalid request') !== false): ?>
                            <div class="alert alert-danger"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <div class="table-responsive">
                            <table class="table table-hover" id="deviceTable">
                                <thead>
                                    <tr>
                                        <th>Device ID</th>
                                        <th>User Name</th>
                                        <th>Status</th>
                                        <th>Registration Date</th>
                                        <th>Expiration Date</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($devices)): ?>
                                        <tr><td colspan="6" class="text-center">No devices registered yet.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($devices as $device): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($device['device_id']); ?></td>
                                            <td><?php echo htmlspecialchars($device['user_name']); ?></td>
                                            <td>
                                                <?php
                                                $status_class = '';
                                                $display_status = 'Pending';
                                                if ($device['approved'] == 1) {
                                                    $status_class = 'status-approved';
                                                    $display_status = 'Approved';
                                                    if ($device['expiration_date'] && strtotime($device['expiration_date']) < time()) {
                                                        $status_class = 'status-expired';
                                                        $display_status = 'Expired';
                                                    }
                                                } else {
                                                    $status_class = 'status-pending';
                                                }
                                                echo "<span class='{$status_class}'>{$display_status}</span>";
                                                ?>
                                            </td>
                                            <td><?php echo htmlspecialchars($device['registration_date']); ?></td>
                                            <td><?php echo htmlspecialchars($device['expiration_date'] ?? 'N/A'); ?></td>
                                            <td class="device-actions">
                                                <?php if ($device['approved'] == 0): ?>
                                                    <form method="POST">
                                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                        <input type="hidden" name="device_action" value="approve">
                                                        <input type="hidden" name="device_id_to_act" value="<?php echo htmlspecialchars($device['device_id']); ?>">
                                                        <input type="number" name="expiration_days" placeholder="Days" class="expiration-input form-control form-control-sm d-inline-block w-auto" value="<?php echo htmlspecialchars($default_expiration_days); ?>">
                                                        <button type="submit" class="btn btn-sm approve-btn">Approve</button>
                                                    </form>
                                                <?php else: ?>
                                                    <form method="POST">
                                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                        <input type="hidden" name="device_action" value="deny">
                                                        <input type="hidden" name="device_id_to_act" value="<?php echo htmlspecialchars($device['device_id']); ?>">
                                                        <button type="submit" class="btn btn-sm deny-btn">Deny</button>
                                                    </form>
                                                    <form method="POST">
                                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                        <input type="hidden" name="device_action" value="set_expiration">
                                                        <input type="hidden" name="device_id_to_act" value="<?php echo htmlspecialchars($device['device_id']); ?>">
                                                        <input type="number" name="expiration_days" placeholder="Days" class="expiration-input form-control form-control-sm d-inline-block w-auto" value="30">
                                                        <button type="submit" class="btn btn-sm set-exp-btn">Set Exp.</button>
                                                    </form>
                                                <?php endif; ?>
                                                <form method="POST" onsubmit="return confirm('Are you sure you want to delete this device? This action cannot be undone.');">
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="device_action" value="delete">
                                                    <input type="hidden" name="device_id_to_act" value="<?php echo htmlspecialchars($device['device_id']); ?>">
                                                    <button type="submit" class="btn btn-sm delete-btn">Delete</button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row" id="deviceActivityLogSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Device Activity Log</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="deviceActivityLogTable">
                                <thead>
                                    <tr>
                                        <th>Date/Time</th>
                                        <th>Device ID</th>
                                        <th>Action</th>
                                        <th>Old Status</th>
                                        <th>New Status</th>
                                        <th>Expiration Change</th>
                                        <th>Action By</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($device_logs_full)): ?>
                                        <tr><td colspan="7" class="text-center">No device activity recorded yet.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($device_logs_full as $log): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars(date('Y-m-d H:i:s', strtotime($log['action_date']))); ?></td>
                                            <td><?php echo htmlspecialchars($log['device_id']); ?></td>
                                            <td>
                                                <span class="badge bg-<?php
                                                    if ($log['action'] == 'approved' || $log['action'] == 'registered_and_approved' || $log['action'] == 'checked_in') echo 'success';
                                                    elseif ($log['action'] == 'denied') echo 'danger';
                                                    elseif ($log['action'] == 'expiration_set' || $log['action'] == 'pending_checkin') echo 'info';
                                                    elseif ($log['action'] == 'deleted') echo 'secondary';
                                                    elseif ($log['action'] == 'registered') echo 'primary';
                                                    elseif ($log['action'] == 'expired_checkin') echo 'purple'; // Custom color
                                                    else echo 'dark';
                                                ?>"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $log['action']))); ?></span>
                                            </td>
                                            <td><?php echo htmlspecialchars($log['old_status'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($log['new_status'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($log['expiration_change'] ?? 'N/A'); ?></td>
                                            <td><?php echo htmlspecialchars($log['action_by'] ?? 'System'); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php if ($is_owner): // Only show these sections for owners ?>
        <div class="row" id="addAdminUserSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Add New Admin User</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message && (strpos($message, 'Admin user') === 0) && strpos($message, 'Error') === false): /* Show success message for adding admin user */?>
                            <div class="alert alert-success"><?php echo $message; ?></div>
                        <?php elseif ($message && (strpos($message, 'Username') === 0 && strpos($message, 'exists') !== false)): ?>
                             <div class="alert alert-warning"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <div class="row g-3">
                                <div class="col-md-5">
                                    <label for="new_admin_username" class="form-label">Username</label>
                                    <input type="text" class="form-control" id="new_admin_username" name="new_admin_username" placeholder="Enter new admin username" required>
                                </div>
                                <div class="col-md-5">
                                    <label for="new_admin_password" class="form-label">Password</label>
                                    <input type="password" class="form-control" id="new_admin_password" name="new_admin_password" placeholder="Enter password" required>
                                </div>
                                <div class="col-md-2 d-flex align-items-end">
                                    <button type="submit" name="add_admin_user_submit" class="btn btn-primary w-100"><i class="fas fa-user-plus me-2"></i>Add Admin</button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <div class="row" id="adminUserListSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Admin User List</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message && (strpos($message, 'status toggled') !== false || strpos($message, 'User deleted') !== false || strpos($message, 'cannot change your own') !== false || strpos($message, 'Error processing user action') !== false || strpos($message, 'Password for user') !== false)): ?>
                            <div class="alert <?php echo (strpos($message, 'Error') !== false || strpos($message, 'cannot') !== false) ? 'alert-warning' : (strpos($message, 'Password for user') !== false ? 'alert-info' : 'alert-success'); ?>"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <div class="table-responsive">
                            <table class="table table-hover" id="userTable">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Role</th> <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($users)): ?>
                                        <tr><td colspan="4" class="text-center">No admin users registered yet.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($users as $user): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($user['id']); ?></td>
                                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                                            <td>
                                                <?php if ($user['is_owner'] == 1): ?>
                                                    <span class="badge owner-badge">Owner</span>
                                                <?php elseif ($user['is_admin'] == 1): ?>
                                                    <span class="badge bg-success">Admin</span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary">User</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="user-actions">
                                                <?php
                                                $disable_self_action = ($user['id'] == $_SESSION['user_id']) ? 'disabled title="Cannot modify your own account"' : '';
                                                // An owner can toggle admin status of other users, but cannot toggle another owner's status if they are not the owner themselves
                                                // An owner can toggle an admin's status to non-admin and vice-versa.
                                                // An owner can only delete themselves if there's another owner.
                                                ?>
                                                <form method="POST" <?php echo $disable_self_action; ?>>
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="user_action" value="toggle_admin">
                                                    <input type="hidden" name="user_id_to_act" value="<?php echo htmlspecialchars($user['id']); ?>">
                                                    <button type="submit" class="btn btn-sm toggle-admin-btn"
                                                        <?php echo $disable_self_action; ?>
                                                        <?php echo ($user['is_owner'] == 1 && $user['id'] != $_SESSION['user_id']) ? 'disabled title="Cannot modify another owner\'s status"' : ''; ?>
                                                        >
                                                        <?php echo ($user['is_admin'] == 1) ? 'Demote Admin' : 'Promote Admin'; ?>
                                                    </button>
                                                </form>
                                                <button type="button" class="btn btn-sm reset-password-btn" data-bs-toggle="modal" data-bs-target="#resetPasswordModal" data-user-id="<?php echo htmlspecialchars($user['id']); ?>" data-username="<?php echo htmlspecialchars($user['username']); ?>">Reset Pass</button>

                                                <form method="POST" onsubmit="return confirm('Are you sure you want to delete user <?php echo htmlspecialchars($user['username']); ?>? This action cannot be undone.');" <?php echo $disable_self_action; ?>>
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="user_action" value="delete_user">
                                                    <input type="hidden" name="user_id_to_act" value="<?php echo htmlspecialchars($user['id']); ?>">
                                                    <button type="submit" class="btn btn-sm delete-btn"
                                                        <?php
                                                        // Prevent deleting the last owner, or an owner deleting themselves if they are the only owner
                                                        $is_last_owner = ($user['is_owner'] == 1 && $owner_count <= 1);
                                                        if ($is_last_owner && $user['id'] == $_SESSION['user_id']) {
                                                            echo 'disabled title="Cannot delete the last owner account (yourself)"';
                                                        } elseif ($is_last_owner) {
                                                            echo 'disabled title="Cannot delete the last owner account"';
                                                        }
                                                        ?>
                                                        >
                                                        Delete
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row" id="adminActivityLogSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Admin Activity Log</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="adminActivityLogTable">
                                <thead>
                                    <tr>
                                        <th>Date/Time</th>
                                        <th>Admin User</th>
                                        <th>Action</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($user_logs)): ?>
                                        <tr><td colspan="4" class="text-center">No admin activity recorded yet.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($user_logs as $log): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars(date('Y-m-d H:i:s', strtotime($log['action_date']))); ?></td>
                                            <td><?php echo htmlspecialchars($log['username']); ?></td>
                                            <td><span class="badge bg-primary"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $log['action']))); ?></span></td>
                                            <td><?php echo htmlspecialchars($log['details'] ?? 'N/A'); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <div class="row" id="settingsSection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">General Settings</h5>
                    </div>
                    <div class="card-body">
                        <?php if ($message && (strpos($message, 'Settings updated') !== false || strpos($message, 'Error updating settings') !== false)): ?>
                            <div class="alert <?php echo (strpos($message, 'Error') !== false) ? 'alert-danger' : 'alert-success'; ?>"><?php echo $message; ?></div>
                        <?php endif; ?>
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <div class="mb-3">
                                <label for="site_name" class="form-label">Site Name</label>
                                <input type="text" class="form-control" id="site_name" name="site_name" value="<?php echo htmlspecialchars($site_name); ?>" required>
                                <div class="form-text">This name will appear in the dashboard title and branding.</div>
                            </div>
                            <div class="mb-3">
                                <label for="default_expiration_days" class="form-label">Default Device Expiration (Days)</label>
                                <input type="number" class="form-control" id="default_expiration_days" name="default_expiration_days" value="<?php echo htmlspecialchars($default_expiration_days); ?>" min="1" required>
                                <div class="form-text">Sets the default number of days for new device approvals.</div>
                            </div>
                            <button type="submit" name="update_settings_submit" class="btn btn-primary"><i class="fas fa-save me-2"></i>Save Settings</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <div class="row" id="notificationHistorySection">
            <div class="col-lg-12 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Notification History</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-hover" id="notificationHistoryTable">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Message</th>
                                        <th>Type</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($notifications)): ?>
                                        <tr><td colspan="5" class="text-center">No notifications in history.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach ($notifications as $notification): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars(date('Y-m-d H:i', strtotime($notification['created_at']))); ?></td>
                                            <td><?php echo htmlspecialchars($notification['message']); ?></td>
                                            <td><span class="badge bg-<?php echo htmlspecialchars($notification['type']); ?>"><?php echo htmlspecialchars(ucfirst($notification['type'])); ?></span></td>
                                            <td><?php echo ($notification['read_status'] == 1) ? 'Read' : 'Unread'; ?></td>
                                            <td>
                                                <?php if ($notification['read_status'] == 0): ?>
                                                <form method="POST" class="d-inline mark-read-form">
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                                    <input type="hidden" name="mark_notification_read" value="1">
                                                    <input type="hidden" name="notification_id" value="<?php echo htmlspecialchars($notification['id']); ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-primary">Mark as Read</button>
                                                </form>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <div class="row mb-4">
            <div class="col-lg-8 mb-4">
                <div class="card h-100">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">Traffic Overview</h5>
                        <div class="dropdown">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="trafficDropdown" data-bs-toggle="dropdown">
                                This Month
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li><a class="dropdown-item" href="#" data-chart-period="today">Today</a></li>
                                <li><a class="dropdown-item" href="#" data-chart-period="this-week">This Week</a></li>
                                <li><a class="dropdown-item" href="#" data-chart-period="this-month">This Month</a></li>
                                <li><a class="dropdown-item" href="#" data-chart-period="this-year">This Year</a></li>
                            </ul>
                        </div>
                    </div>
                    <div class="card-body">
                        <canvas id="trafficChart" height="300"></canvas>
                    </div>
                </div>
            </div>

            <div class="col-lg-4 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Traffic Sources</h5>
                    </div>
                    <div class="card-body">
                        <canvas id="trafficSourcesChart" height="300"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Recent Device Actions</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>Device ID</th>
                                        <th>Action</th>
                                        <th>Action By</th>
                                        <th>Date</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty(array_slice($device_logs_full, 0, 5))): ?>
                                        <tr><td colspan="4" class="text-center">No recent device actions.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach (array_slice($device_logs_full, 0, 5) as $log): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($log['device_id']); ?></td>
                                            <td><span class="badge bg-<?php
                                                if ($log['action'] == 'approved' || $log['action'] == 'registered_and_approved' || $log['action'] == 'checked_in') echo 'success';
                                                elseif ($log['action'] == 'denied') echo 'danger';
                                                elseif ($log['action'] == 'expiration_set' || $log['action'] == 'pending_checkin') echo 'info';
                                                elseif ($log['action'] == 'deleted') echo 'secondary';
                                                elseif ($log['action'] == 'registered') echo 'primary';
                                                elseif ($log['action'] == 'expired_checkin') echo 'purple';
                                                else echo 'dark';
                                            ?>"><?php echo htmlspecialchars(ucfirst(str_replace('_', ' ', $log['action']))); ?></span></td>
                                            <td><?php echo htmlspecialchars($log['action_by']); ?></td>
                                            <td><?php echo htmlspecialchars(date('Y-m-d H:i', strtotime($log['action_date']))); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Calendar</h5>
                    </div>
                    <div class="card-body">
                        <div id="calendar"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Recent Users</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th>User</th>
                                        <th>Role</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($users)): ?>
                                        <tr><td colspan="3" class="text-center">No users registered yet.</td></tr>
                                    <?php endif; ?>
                                    <?php foreach (array_slice($users, 0, 5) as $user): // Display top 5 recent users ?>
                                        <tr>
                                            <td>
                                                <div class="d-flex align-items-center">
                                                    <img src="https://via.placeholder.com/30" class="avatar me-2" alt="User">
                                                    <span><?php echo htmlspecialchars($user['username']); ?></span>
                                                </div>
                                            </td>
                                            <td>
                                                <?php if ($user['is_owner'] == 1): ?>
                                                    <span class="badge owner-badge">Owner</span>
                                                <?php elseif ($user['is_admin'] == 1): ?>
                                                    <span class="badge bg-success">Admin</span>
                                                <?php else: ?>
                                                    <span class="badge bg-secondary">User</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?php
                                                // Simplified status based on roles for demonstration
                                                if ($user['is_owner'] == 1 || $user['is_admin'] == 1) {
                                                    echo '<span class="status-indicator status-online"></span> Active';
                                                } else {
                                                    echo '<span class="status-indicator status-offline"></span> Inactive';
                                                }
                                                ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-lg-6 mb-4">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0">Project Kanban Board</h5>
                    </div>
                    <div class="card-body">
                        <div class="kanban-board">
                            <div class="kanban-column">
                                <div class="kanban-column-header">To Do</div>
                                <div class="kanban-item">
                                    <h6>Design Dashboard</h6>
                                    <p class="small text-muted mb-2">Create mockups for new dashboard</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-primary">Design</span>
                                        <small class="text-muted">Due tomorrow</small>
                                    </div>
                                </div>
                                <div class="kanban-item">
                                    <h6>API Documentation</h6>
                                    <p class="small text-muted mb-2">Write API documentation for developers</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-info">Documentation</span>
                                        <small class="text-muted">Due in 3 days</s
                                    </div>
                                </div>
                            </div>
                            <div class="kanban-column">
                                <div class="kanban-column-header">In Progress</div>
                                <div class="kanban-item">
                                    <h6>Implement Dark Mode</h6>
                                    <p class="small text-muted mb-2">Add dark mode toggle functionality</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-success">Frontend</span>
                                        <small class="text-muted">Due in 2 days</s
                                    </div>
                                </div>
                                <div class="kanban-item">
                                    <h6>User Authentication</h6>
                                    <p class="small text-muted mb-2">Implement JWT authentication</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-danger">Backend</span>
                                        <small class="text-muted">Due in 5 days</small>
                                    </div>
                                </div>
                            </div>
                            <div class="kanban-column">
                                <div class="kanban-column-header">Review</div>
                                <div class="kanban-item">
                                    <h6>Mobile Responsiveness</h6>
                                    <p class="small text-muted mb-2">Test on various mobile devices</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-warning">Testing</span>
                                        <small class="text-muted">Due today</small>
                                    </div>
                                </div>
                            </div>
                            <div class="kanban-column">
                                <div class="kanban-column-header">Done</div>
                                <div class="kanban-item">
                                    <h6>Database Schema</h6>
                                    <p class="small text-muted mb-2">Design and implement database schema</p>
                                    <div class="d-flex justify-content-between align-items-center">
                                        <span class="badge bg-secondary">Database</span>
                                        <small class="text-muted">Completed</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <footer class="footer mt-auto py-3 bg-light">
        <div class="container-fluid">
            <div class="row">
                <div class="col-md-6">
                    <span class="text-muted">&copy; 2025 <?php echo htmlspecialchars($site_name); ?>. All rights reserved.</span>
                </div>
                <div class="col-md-6 text-md-end">
                    <span class="text-muted">Version 2.0.0 | Developed with <i class="fas fa-heart text-danger"></i> by AshxDeath</span>
                </div>
            </div>
        </div>
    </footer>

    <div class="fab" data-bs-toggle="modal" data-bs-target="#quickActionModal">
        <i class="fas fa-plus"></i>
    </div>

    <div class="back-to-top">
        <i class="fas fa-arrow-up"></i>
    </div>

    <div class="modal fade" id="quickActionModal" tabindex="-1" aria-labelledby="quickActionModalLabel"
        aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header gradient-bg">
                    <h5 class="modal-title text-white" id="quickActionModalLabel">Quick Actions</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="row g-3">
                        <?php if ($is_owner): // Only show "Add Admin User" quick action for owners ?>
                        <div class="col-md-6">
                            <a href="#addAdminUserSection" class="card text-decoration-none text-center p-3 hover-scale quick-action-link">
                                <i class="fas fa-user-plus fa-2x text-primary mb-2"></i>
                                <h6 class="mb-0">Add Admin User</h6>
                            </a>
                        </div>
                        <?php endif; ?>
                        <div class="col-md-6">
                            <a href="#addDeviceSection" class="card text-decoration-none text-center p-3 hover-scale quick-action-link">
                                <i class="fas fa-mobile-alt fa-2x text-info mb-2"></i>
                                <h6 class="mb-0">Add Device</h6>
                            </a>
                        </div>
                        <div class="col-md-6">
                            <a href="#" class="card text-decoration-none text-center p-3 hover-scale" id="quickCreateReport">
                                <i class="fas fa-file-alt fa-2x text-success mb-2"></i>
                                <h6 class="mb-0">Create Report</h6>
                            </a>
                        </div>
                        <div class="col-md-6">
                            <a href="#" class="card text-decoration-none text-center p-3 hover-scale" id="quickAddEvent">
                                <i class="fas fa-calendar-plus fa-2x text-info mb-2"></i>
                                <h6 class="mb-0">Add Event</h6>
                            </a>
                        </div>
                        <div class="col-md-6">
                            <a href="#" class="card text-decoration-none text-center p-3 hover-scale" id="quickSendMessage">
                                <i class="fas fa-envelope fa-2x text-warning mb-2"></i>
                                <h6 class="mb-0">Send Message</h6>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="modal fade" id="resetPasswordModal" tabindex="-1" aria-labelledby="resetPasswordModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header bg-secondary text-white">
                    <h5 class="modal-title" id="resetPasswordModalLabel">Reset Password for <span id="resetUsernameDisplay"></span></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="user_action" value="reset_password">
                    <input type="hidden" name="user_id_to_act" id="resetUserIdToAct">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label for="newPassword" class="form-label">New Password</label>
                            <input type="password" class="form-control" id="newPassword" name="new_password" required>
                        </div>
                        <div class="mb-3">
                            <label for="confirmNewPassword" class="form-label">Confirm New Password</label>
                            <input type="password" class="form-control" id="confirmNewPassword" required>
                            <div class="invalid-feedback">Passwords do not match.</div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="submit" class="btn btn-primary" id="resetPasswordSubmitBtn" disabled>Reset Password</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.3/main.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.4/js/dataTables.bootstrap5.min.js"></script>
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

        // Initialize AOS animation
        AOS.init({
            duration: 800,
            easing: 'ease-in-out',
            once: true
        });

        // Dark mode toggle
        const darkModeSwitch = document.getElementById('darkModeSwitch');
        const body = document.body;
        const toggleDarkMode = document.getElementById('toggleDarkMode');

        // Check for saved dark mode preference
        if (localStorage.getItem('darkMode') === 'enabled') {
            body.classList.add('dark-mode');
            darkModeSwitch.checked = true;
        }

        darkModeSwitch.addEventListener('change', function() {
            if (this.checked) {
                body.classList.add('dark-mode');
                localStorage.setItem('darkMode', 'enabled');
                showCustomToast('Appearance', 'Dark mode enabled!', 'dark');
            } else {
                body.classList.remove('dark-mode');
                localStorage.setItem('darkMode', 'disabled');
                showCustomToast('Appearance', 'Dark mode disabled!', 'light');
            }
        });

        toggleDarkMode.addEventListener('click', function() {
            darkModeSwitch.checked = !darkModeSwitch.checked;
            darkModeSwitch.dispatchEvent(new Event('change'));
        });

        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });

        // Initialize popovers
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(function (popoverTriggerEl) {
            return new bootstrap.Popover(popoverTriggerEl);
        });

        // Charts
        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart').getContext('2d');
        const trafficChart = new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
                datasets: [{
                    label: 'Visitors',
                    data: [12000, 19000, 15000, 18000, 22000, 25000, 21000, 24000, 28000, 26000, 30000, 32000],
                    borderColor: 'rgba(0, 188, 212, 1)', /* Cyan */
                    backgroundColor: 'rgba(0, 188, 212, 0.1)', /* Cyan with opacity */
                    borderWidth: 2,
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
                    tooltip: {
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            drawBorder: false
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });

        // Traffic Sources Chart
        const trafficSourcesCtx = document.getElementById('trafficSourcesChart').getContext('2d');
        const trafficSourcesChart = new Chart(trafficSourcesCtx, {
            type: 'doughnut',
            data: {
                labels: ['Direct', 'Social', 'Referral', 'Organic'],
                datasets: [{
                    data: [35, 25, 20, 20],
                    backgroundColor: [
                        'rgba(0, 188, 212, 0.8)', /* Cyan */
                        'rgba(255, 193, 7, 0.8)', /* Warning/Yellow */
                        'rgba(40, 167, 69, 0.8)', /* Success/Green */
                        'rgba(13, 110, 253, 0.8)' /* Info/Light Blue */
                    ],
                    borderColor: [
                        'rgba(0, 188, 212, 1)',
                        'rgba(255, 193, 7, 1)',
                        'rgba(40, 167, 69, 1)',
                        'rgba(13, 110, 253, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                },
                cutout: '70%'
            }
        });

        // Show initial toast notification from PHP
        // This relies on your PHP passing a message variable.
        // I will assume $message is empty if no action was just taken.
        <?php if (!empty($message)): ?>
            showCustomToast('Status', '<?php echo $message; ?>', '<?php
                if (strpos($message, "Error") === 0 || strpos($message, "cannot") !== false || strpos($message, "Invalid request") !== false) {
                    echo "danger";
                } elseif (strpos($message, "successfully") !== false || strpos($message, "approved") !== false || strpos($message, "added") !== false || strpos($message, "toggled") !== false) {
                    echo "success";
                } elseif (strpos($message, "exists") !== false || strpos($message, "required") !== false || strpos($message, "pending") !== false) {
                    echo "warning";
                } else {
                    echo "info";
                }
            ?>');
        <?php endif; ?>

        // Initialize FullCalendar
        document.addEventListener('DOMContentLoaded', function() {
            const calendarEl = document.getElementById('calendar');
            const calendar = new FullCalendar.Calendar(calendarEl, {
                initialView: 'dayGridMonth',
                headerToolbar: {
                    left: 'prev,next today',
                    center: 'title',
                    right: 'dayGridMonth,timeGridWeek,timeGridDay'
                },
                events: [
                    {
                        title: 'Team Meeting',
                        start: new Date(),
                        end: new Date(new Date().setHours(new Date().getHours() + 1)),
                        backgroundColor: 'rgba(0, 188, 212, 0.8)' /* Primary Cyan */
                    },
                    {
                        title: 'Product Launch',
                        start: new Date(new Date().setDate(new Date().getDate() + 3)),
                        backgroundColor: 'rgba(40, 167, 69, 0.8)' /* Success Green */
                    },
                    {
                        title: 'Client Call',
                        start: new Date(new Date().setDate(new Date().getDate() + 5)),
                        backgroundColor: 'rgba(220, 53, 69, 0.8)' /* Danger Red */
                    }
                ]
            });
            calendar.render();
            console.log('FullCalendar initialized.');
        });

        // Back to top button
        const backToTopButton = document.querySelector('.back-to-top');
        window.addEventListener('scroll', function() {
            if (window.pageYOffset > 300) {
                backToTopButton.style.display = 'flex';
            } else {
                backToTopButton.style.display = 'none';
            }
        });

        backToTopButton.addEventListener('click', function() {
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
            console.log('Back to top clicked.');
        });

        // Initialize DataTables
        $(document).ready(function() {
            // Device Table
            if ($.fn.DataTable.isDataTable('#deviceTable')) {
                $('#deviceTable').DataTable().destroy();
            }
            $('#deviceTable').DataTable({
                responsive: true,
                paging: true,
                searching: true,
                info: true,
                "aoColumns": [
                    null,
                    null,
                    null,
                    null,
                    null,
                    { "bSortable": false, "bSearchable": false }
                ]
            });

            // User Table
            if ($.fn.DataTable.isDataTable('#userTable')) {
                $('#userTable').DataTable().destroy();
            }
            $('#userTable').DataTable({
                responsive: true,
                paging: true,
                searching: true,
                info: true,
                "aoColumns": [
                    null,
                    null,
                    null,
                    { "bSortable": false, "bSearchable": false }
                ]
            });

            // Device Activity Log Table
            if ($.fn.DataTable.isDataTable('#deviceActivityLogTable')) { //
                $('#deviceActivityLogTable').DataTable().destroy(); //
            }
            $('#deviceActivityLogTable').DataTable({ //
                responsive: true, //
                paging: true, //
                searching: true, //
                info: true, //
                "order": [[ 0, "desc" ]], // Order by first column (Date/Time) descending
                "aoColumns": [ //
                    null, null, null, null, null, null, null //
                ]
            });

            // Admin Activity Log Table
            if ($.fn.DataTable.isDataTable('#adminActivityLogTable')) { //
                $('#adminActivityLogTable').DataTable().destroy(); //
            }
            $('#adminActivityLogTable').DataTable({ //
                responsive: true, //
                paging: true, //
                searching: true, //
                info: true, //
                "order": [[ 0, "desc" ]], // Order by first column (Date/Time) descending
                "aoColumns": [ //
                    null, null, null, null //
                ]
            });

            // Notification History Table
            if ($.fn.DataTable.isDataTable('#notificationHistoryTable')) { //
                $('#notificationHistoryTable').DataTable().destroy(); //
            }
            $('#notificationHistoryTable').DataTable({ //
                responsive: true, //
                paging: true, //
                searching: true, //
                info: true, //
                "order": [[ 0, "desc" ]], // Order by first column (Date) descending
                "aoColumns": [ //
                    null, null, null, null, { "bSortable": false, "bSearchable": false } //
                ]
            });

            console.log('DataTables initialized.');
        });

        // Drag and drop for kanban board (retained as is, provides interactivity)
        const kanbanItems = document.querySelectorAll('.kanban-item');
        kanbanItems.forEach(item => {
            item.setAttribute('draggable', true);

            item.addEventListener('dragstart', function() {
                this.classList.add('dragging');
                console.log('Kanban item drag started.');
            });

            item.addEventListener('dragend', function() {
                this.classList.remove('dragging');
                console.log('Kanban item drag ended.');
            });
        });

        const kanbanColumns = document.querySelectorAll('.kanban-column');
        kanbanColumns.forEach(column => {
            column.addEventListener('dragover', function(e) {
                e.preventDefault();
                const draggingItem = document.querySelector('.dragging');
                const afterElement = getDragAfterElement(this, e.clientY);

                if (afterElement) {
                    afterElement.parentNode.insertBefore(draggingItem, afterElement);
                } else {
                    this.appendChild(draggingItem);
                }
            });
            column.addEventListener('drop', function(e) {
                e.preventDefault();
                const draggingItem = document.querySelector('.dragging');
                if (draggingItem) {
                    this.appendChild(draggingItem);
                    console.log(`Kanban item dropped into column: ${this.querySelector('.kanban-column-header').textContent}`);
                }
            });
        });

        function getDragAfterElement(container, y) {
            const draggableElements = [...container.querySelectorAll('.kanban-item:not(.dragging)')];

            return draggableElements.reduce((closest, child) => {
                const box = child.getBoundingClientRect();
                const offset = y - box.top - box.height / 2;

                if (offset < 0 && offset > closest.offset) {
                    return { offset: offset, element: child };
                } else {
                    return closest;
                }
            }, { offset: Number.NEGATIVE_INFINITY }).element;
        }

        // --- All Button Functionality Enhancements ---

        // Navbar Links
        document.getElementById('homeNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Home page (simulated).', 'info');
            console.log('Home Nav Link clicked.');
        });

        document.getElementById('contactNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Contact page (simulated).', 'info');
            console.log('Contact Nav Link clicked.');
        });

        // Navbar Search
        document.getElementById('navbarSearchForm')?.addEventListener('submit', function(e) {
            e.preventDefault();
            const searchTerm = document.getElementById('navbarSearchInput').value;
            if (searchTerm) {
                showCustomToast('Search', `Searching for "${searchTerm}" (simulated).`, 'secondary');
                console.log('Navbar Search submitted:', searchTerm);
            } else {
                showCustomToast('Search', 'Please enter a search term.', 'warning');
            }
        });

        // Notifications Dropdown Actions
        document.getElementById('markAllNotificationsReadBtn')?.addEventListener('click', function(e) { //
            e.preventDefault(); //
            const csrfToken = document.querySelector('input[name="csrf_token"]').value; //
            $.ajax({ //
                url: 'index.php', // Current page
                type: 'POST', //
                data: { //
                    csrf_token: csrfToken, //
                    mark_all_notifications_read: 1 //
                },
                success: function() { //
                    showCustomToast('Notifications', 'All notifications marked as read!', 'success'); //
                    // Reload the page or update UI dynamically
                    location.reload(); //
                },
                error: function(xhr, status, error) { //
                    showCustomToast('Error', 'Failed to mark notifications as read.', 'danger'); //
                    console.error('AJAX error:', status, error); //
                }
            });
            console.log('Mark all notifications as read clicked.');
        });

        document.querySelectorAll('.notification-item').forEach(item => { //
            item.addEventListener('click', function(e) { //
                e.preventDefault(); //
                const notificationId = this.dataset.notificationId; //
                const csrfToken = document.querySelector('input[name="csrf_token"]').value; //
                if (notificationId) { //
                    // Make AJAX call to mark as read
                    $.ajax({ //
                        url: 'index.php', // Current page
                        type: 'POST', //
                        data: { //
                            csrf_token: csrfToken, //
                            mark_notification_read: 1, //
                            notification_id: notificationId //
                        },
                        success: function() { //
                            showCustomToast('Notification', 'Notification marked as read.', 'info'); //
                            // Visually update the item as read
                            item.classList.remove('fw-bold'); //
                            // Optionally remove the badge from the bell icon or refresh its count
                            // For simplicity, a full reload is often used after such changes in small apps
                            location.reload(); //
                        },
                        error: function(xhr, status, error) { //
                            showCustomToast('Error', 'Failed to mark notification as read.', 'danger'); //
                            console.error('AJAX error:', status, error); //
                        }
                    });
                    console.log('Notification item clicked:', notificationId);
                }
            });
        });

        document.getElementById('viewAllNotifications')?.addEventListener('click', function(e) { //
            e.preventDefault(); //
            document.getElementById('notificationHistorySection').scrollIntoView({ behavior: 'smooth' }); //
            showCustomToast('Navigation', 'Viewing all notifications.', 'info'); //
            console.log('View all notifications clicked.');
        });

        // User Dropdown
        document.getElementById('userProfileLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('User Action', 'Navigating to User Profile (simulated).', 'info');
            console.log('User Profile link clicked.');
        });
        document.getElementById('userSettingsLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('settingsSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('User Action', 'Navigating to General Settings.', 'info');
            console.log('User Settings link clicked.');
        });
        // userLogoutLink already points to logout.php, which handles session destruction.

        // Sidebar Menu Links
        // Dashboard link already points to index.php, which reloads and updates data.
        document.getElementById('dashboardNavLink')?.addEventListener('click', function(e) {
            // Already handled by href="index.php" which causes a full page reload.
            // Adding a toast for user feedback.
            showCustomToast('Navigation', 'Navigating to Dashboard.', 'primary');
            console.log('Dashboard Nav Link clicked.');
        });

        // Device Management Sidebar Links
        document.getElementById('addDeviceNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('addDeviceSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Add Device section.', 'info');
            console.log('Add Device Nav Link clicked.');
        });

        document.getElementById('listDevicesNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('deviceTableSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Device List section.', 'info');
            console.log('List Devices Nav Link clicked.');
        });

        document.getElementById('deviceActivityLogNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('deviceActivityLogSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Device Activity Log section.', 'info');
            console.log('Device Activity Log Nav Link clicked.');
        });

        // User Management Sidebar Links
        document.getElementById('addAdminUserNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('addAdminUserSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Add Admin User section.', 'info');
            console.log('Add Admin User Nav Link clicked.');
        });

        document.getElementById('adminUserListNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('adminUserListSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Admin User List section.', 'info');
            console.log('Admin User List Nav Link clicked.');
        });

        document.getElementById('adminActivityLogNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('adminActivityLogSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Admin Activity Log section.', 'info');
            console.log('Admin Activity Log Nav Link clicked.');
        });

        // Settings Sidebar Links
        document.getElementById('generalSettingsNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('settingsSection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to General Settings.', 'info');
            console.log('General Settings Nav Link clicked.');
        });
        document.getElementById('notificationsHistoryNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            document.getElementById('notificationHistorySection').scrollIntoView({ behavior: 'smooth' });
            showCustomToast('Navigation', 'Scrolling to Notification History.', 'info');
            console.log('Notification History Nav Link clicked.');
        });
        document.getElementById('securityNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Settings', 'Opening "Security" settings (simulated).', 'danger');
            console.log('Security Nav Link clicked.');
        });

        // Other Sidebar Links
        document.getElementById('analyticsNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Analytics.', 'primary');
            console.log('Analytics Nav Link clicked.');
        });
        document.getElementById('reportsNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Reports.', 'primary');
            console.log('Reports Nav Link clicked.');
        });
        document.getElementById('calendarNavLink')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Calendar.', 'primary');
            console.log('Calendar Nav Link clicked.');
        });

        // Sidebar Search
        document.getElementById('sidebarSearchBtn')?.addEventListener('click', function(e) {
            e.preventDefault();
            const searchTerm = document.getElementById('sidebarSearchInput').value;
            if (searchTerm) {
                showCustomToast('Search', `Sidebar searching for "${searchTerm}" (simulated).`, 'secondary');
                console.log('Sidebar Search submitted:', searchTerm);
            } else {
                showCustomToast('Search', 'Please enter a search term for sidebar.', 'warning');
            }
        });

        // Traffic Overview Dropdown Items (Chart Data Change Simulation)
        const trafficDropdownItems = document.querySelectorAll('#trafficDropdown + .dropdown-menu .dropdown-item');
        trafficDropdownItems.forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                const period = this.dataset.chartPeriod;
                document.getElementById('trafficDropdown').textContent = this.textContent;
                showCustomToast('Chart Update', `Updating traffic chart for ${this.textContent} (simulated data).`, 'info');
                console.log(`Traffic chart period changed to: ${period}`);

                // Simulate updating chart data
                let newData;
                let newLabels;
                if (period === 'today') {
                    newLabels = ['1AM', '4AM', '7AM', '10AM', '1PM', '4PM', '7PM', '10PM'];
                    newData = [150, 200, 350, 600, 750, 900, 800, 450];
                } else if (period === 'this-week') {
                    newLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
                    newData = [3000, 4500, 3800, 5200, 6000, 7500, 5000];
                } else if (period === 'this-month') {
                    newLabels = ['Week 1', 'Week 2', 'Week 3', 'Week 4'];
                    newData = [8000, 12000, 10000, 15000];
                } else if (period === 'this-year') {
                     newLabels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                     newData = [12000, 19000, 15000, 18000, 22000, 25000, 21000, 24000, 28000, 26000, 30000, 32000];
                }
                trafficChart.data.labels = newLabels;
                trafficChart.data.datasets[0].data = newData;
                trafficChart.update();
            });
        });

        // Breadcrumb Home Link
        document.getElementById('breadcrumbHome')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Navigation', 'Navigating to Dashboard Home.', 'info');
            console.log('Breadcrumb Home link clicked.');
        });

        // Quick Actions Modal Buttons
        // These links now scroll to specific sections and close the modal
        document.querySelectorAll('.quick-action-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                if (targetId && targetId.startsWith('#')) {
                    const targetElement = document.getElementById(targetId.substring(1));
                    if (targetElement) {
                        targetElement.scrollIntoView({ behavior: 'smooth' });
                        showCustomToast('Quick Action', `Scrolling to ${this.querySelector('h6').textContent} section.`, 'info');
                        bootstrap.Modal.getInstance(document.getElementById('quickActionModal'))?.hide(); // Close quick action modal
                    }
                }
            });
        });

        document.getElementById('quickCreateReport')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Quick Action', 'Simulating "Create Report" action.', 'success');
            console.log('Quick Create Report button clicked.');
            bootstrap.Modal.getInstance(document.getElementById('quickActionModal'))?.hide();
        });
        document.getElementById('quickAddEvent')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Quick Action', 'Simulating "Add Event" action.', 'success');
            console.log('Quick Add Event button clicked.');
            bootstrap.Modal.getInstance(document.getElementById('quickActionModal'))?.hide();
        });
        document.getElementById('quickSendMessage')?.addEventListener('click', function(e) {
            e.preventDefault();
            showCustomToast('Quick Action', 'Simulating "Send Message" action.', 'success');
            console.log('Quick Send Message button clicked.');
            bootstrap.Modal.getInstance(document.getElementById('quickActionModal'))?.hide();
        });

        // Reset Password Modal Logic
        const resetPasswordModal = document.getElementById('resetPasswordModal'); //
        if (resetPasswordModal) { //
            resetPasswordModal.addEventListener('show.bs.modal', function (event) { //
                const button = event.relatedTarget; //
                const userId = button.getAttribute('data-user-id'); //
                const username = button.getAttribute('data-username'); //

                const modalTitle = resetPasswordModal.querySelector('#resetUsernameDisplay'); //
                const userIdInput = resetPasswordModal.querySelector('#resetUserIdToAct'); //
                const newPasswordInput = resetPasswordModal.querySelector('#newPassword'); //
                const confirmNewPasswordInput = resetPasswordModal.querySelector('#confirmNewPassword'); //
                const resetPasswordSubmitBtn = resetPasswordModal.querySelector('#resetPasswordSubmitBtn'); //

                modalTitle.textContent = username; //
                userIdInput.value = userId; //
                newPasswordInput.value = ''; // Clear previous values
                confirmNewPasswordInput.value = ''; //
                newPasswordInput.classList.remove('is-invalid'); // Clear validation styles
                confirmNewPasswordInput.classList.remove('is-invalid'); //
                resetPasswordSubmitBtn.disabled = true; // Disable submit by default

                // Add event listeners for password validation
                const validatePasswords = () => { //
                    const newPass = newPasswordInput.value; //
                    const confirmPass = confirmNewPasswordInput.value; //

                    if (newPass.length < 6) { // Minimum password length
                        newPasswordInput.classList.add('is-invalid'); //
                        resetPasswordSubmitBtn.disabled = true; //
                        return; //
                    } else {
                        newPasswordInput.classList.remove('is-invalid'); //
                    }

                    if (newPass !== confirmPass) { //
                        confirmNewPasswordInput.classList.add('is-invalid'); //
                        resetPasswordSubmitBtn.disabled = true; //
                    } else {
                        confirmNewPasswordInput.classList.remove('is-invalid'); //
                        resetPasswordSubmitBtn.disabled = false; //
                    }
                };

                newPasswordInput.addEventListener('input', validatePasswords); //
                confirmNewPasswordInput.addEventListener('input', validatePasswords); //
            });

            // Prevent form submission if passwords don't match (client-side validation for UX)
            resetPasswordModal.querySelector('form').addEventListener('submit', function(event) { //
                const newPasswordInput = resetPasswordModal.querySelector('#newPassword'); //
                const confirmNewPasswordInput = resetPasswordModal.querySelector('#confirmNewPassword'); //
                if (newPasswordInput.value !== confirmNewPasswordInput.value) { //
                    event.preventDefault(); //
                    confirmNewPasswordInput.classList.add('is-invalid'); //
                    showCustomToast('Password Reset', 'Passwords do not match.', 'danger'); //
                }
            });
        }

        // UNIFIED SIDEBAR TOGGLE LOGIC
        // This handles both the hamburger (mobile) and chevron (desktop) toggles
        document.addEventListener('DOMContentLoaded', function() {
            const sidebar = document.querySelector('.sidebar');
            const mainContent = document.querySelector('.main-content');
            const sidebarToggle = document.querySelector('.sidebar-toggle'); // Hamburger
            const sidebarMinimizer = document.querySelector('.sidebar-minimizer'); // Chevron

            // Function to set initial state based on screen size
            function setInitialSidebarState() {
                if (window.innerWidth >= 992) { // Desktop
                    sidebar.classList.add('sidebar-expanded'); // Start expanded
                    sidebar.classList.remove('sidebar-collapsed', 'show'); // Ensure no mobile or collapsed classes
                    mainContent.classList.remove('main-content-expanded'); // Initial margin from expanded sidebar
                } else { // Mobile
                    sidebar.classList.remove('sidebar-expanded', 'sidebar-collapsed', 'show'); // Start hidden
                    mainContent.classList.remove('main-content-expanded'); // No extra margin
                }
            }

            // Set initial state on load
            setInitialSidebarState();

            // Re-evaluate state on window resize (important for responsive behavior)
            window.addEventListener('resize', setInitialSidebarState);


            // Event listener for the HAMBURGER icon (mobile toggle)
            if (sidebarToggle) {
                sidebarToggle.addEventListener('click', function(e) {
                    e.preventDefault();
                    sidebar.classList.toggle('show'); // Toggles visibility on mobile
                    // No need to change main-content margin for mobile show/hide
                    console.log('Hamburger (sidebar-toggle) clicked. Sidebar .show toggled.');
                });
            }

            // Event listener for the CHEVRON icon (desktop collapse/expand)
            if (sidebarMinimizer) {
                sidebarMinimizer.addEventListener('click', function(e) {
                    e.preventDefault();
                    sidebar.classList.toggle('sidebar-collapsed');
                    sidebar.classList.toggle('sidebar-expanded');
                    mainContent.classList.toggle('main-content-expanded'); // Adjusts main content margin
                    console.log('Chevron (sidebar-minimizer) clicked. Sidebar collapsed/expanded.');
                });
            }
        });
    </script>
</body>

</html>