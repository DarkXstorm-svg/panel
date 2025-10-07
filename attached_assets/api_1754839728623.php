<?php
// api.php - Endpoint for Python Checker
require_once 'config.php'; // Requires config.php for database connection

$pdo = get_db_connection(); // Gets a PDO database connection

header('Content-Type: application/json'); // Sets the response header to JSON

$response = ['status' => 'error', 'message' => 'Invalid request']; // Default error response

if (isset($_GET['device_id']) && isset($_GET['user_name'])) { // Checks for device_id and user_name parameters
    $device_id = trim($_GET['device_id']); // Trims whitespace from device_id
    $user_name = trim($_GET['user_name']); // Trims whitespace from user_name

    if (empty($device_id) || empty($user_name)) { // Checks if device_id or user_name are empty
        $response = ['status' => 'error', 'message' => 'Missing device_id or user_name']; // Sets error message for missing parameters
    } else {
        try {
            // Check if device exists
            $stmt = $pdo->prepare("SELECT approved, expiration_date FROM devices WHERE device_id = :device_id"); // Prepares SQL statement to select device status
            $stmt->execute([':device_id' => $device_id]); // Executes the statement with device_id
            $device = $stmt->fetch(); // Fetches the device row

            if ($device) { // If device exists
                // Device exists, check approval and expiration
                if ($device['approved'] == 1) { // If device is approved
                    if ($device['expiration_date'] && strtotime($device['expiration_date']) < time()) { // If expiration date exists and is in the past
                        // Device is approved but expired
                        $response = ['status' => 'expired', 'message' => 'Your subscription has expired.']; // Sets expired status
                        // NEW: Log 'expired_checkin' if device was active but is now expired on checkin
                        log_device_action($pdo, $device_id, 'expired_checkin', 'Approved', 'Expired', 'N/A', 'System (API)');
                    } else {
                        // Device is approved and not expired
                        $response = ['status' => 'active', 'message' => 'Subscription active.']; // Sets active status
                        // NEW: Log 'checked_in' event for active devices
                        log_device_action($pdo, $device_id, 'checked_in', 'N/A', 'Active', 'N/A', 'System (API)');
                    }
                } else {
                    // Device exists but is not approved
                    $response = ['status' => 'pending', 'message' => 'Your device is awaiting approval.']; // Sets pending status
                    // NEW: Log 'pending_checkin'
                    log_device_action($pdo, $device_id, 'pending_checkin', 'N/A', 'Pending', 'N/A', 'System (API)');
                }
            } else {
                // Device does not exist, register it as pending
                $stmt = $pdo->prepare("INSERT INTO devices (device_id, user_name, approved, registration_date) VALUES (:device_id, :user_name, 0, CURRENT_DATE)"); // Prepares SQL to insert new device as pending
                $stmt->execute([':device_id' => $device_id, ':user_name' => $user_name]); // Executes the insert statement
                $response = ['status' => 'registered_pending', 'message' => 'Device registered. Awaiting approval.']; // Sets registered pending status
                // Log the registration action
                log_device_action($pdo, $device_id, 'registered', 'N/A', 'Pending', 'N/A', 'System (API)'); //
                // NEW: Add a notification for admins about a new device registration
                // This assumes all admins should get this notification. You might want to get all admin user_ids.
                $admin_users = $pdo->query("SELECT id FROM users WHERE is_admin = 1")->fetchAll(PDO::FETCH_COLUMN);
                foreach($admin_users as $admin_id) {
                    add_notification($pdo, $admin_id, "New device '{$device_id}' registered by '{$user_name}'.", 'info');
                }
            }
        } catch (PDOException $e) {
            error_log("API Error: " . $e->getMessage()); // Logs PDO exceptions
            $response = ['status' => 'error', 'message' => 'Server error during device check.']; // Sets generic server error message
        }
    }
}

echo json_encode($response); // Encodes the response array as JSON and outputs it
?>