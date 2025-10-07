<?php
// logout.php - Fixed version
session_start(); // Starts the session

// NEW: Invalidate the old session ID to prevent session fixation attacks
session_regenerate_id(true);

// Unset all session variables
$_SESSION = array(); // Clear $_SESSION superglobal array

// Destroy the session
session_destroy();

// NEW: Clear any persistent authentication cookies if they were used (e.g., "remember me")
// Assuming no "remember me" functionality exists yet, but this is good practice to include.
// If you implement a "remember me" feature, you would set a cookie, and it needs to be cleared here.
if (isset($_COOKIE[session_name()])) { // Clear the session cookie itself
    setcookie(session_name(), '', time() - 3600, '/');
}
// Example for a hypothetical "remember_me" cookie
// if (isset($_COOKIE['remember_me_token'])) {
//     setcookie('remember_me_token', '', time() - 3600, '/');
// }

// NEW: Set a session variable to display a success message on the login page
$_SESSION['logout_message'] = 'You have been successfully logged out.';

header('Location: login.php'); // Redirects to the login page
exit; // Ensures no further code is executed
?>