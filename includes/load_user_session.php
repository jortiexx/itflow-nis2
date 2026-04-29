<?php

$session_ip = sanitizeInput(getIP());
$session_user_agent = sanitizeInput($_SERVER['HTTP_USER_AGENT']);
$session_user_id = intval($_SESSION['user_id']);

$sql = mysqli_query(
    $mysqli,
    "SELECT * FROM users
     LEFT JOIN user_settings ON users.user_id = user_settings.user_id
     LEFT JOIN user_roles ON user_role_id = role_id
     WHERE users.user_id = $session_user_id"
);

$row = mysqli_fetch_assoc($sql);

$session_name = sanitizeInput($row['user_name']);
$session_email = $row['user_email'];
$session_avatar = $row['user_avatar'];
$session_token = $row['user_token'];
$session_user_type = intval($row['user_type']);
$session_user_archived_at = $row['user_archived_at'];
$session_user_status = intval($row['user_status']);
$session_user_role = intval($row['user_role_id']);
$session_user_role_display = sanitizeInput($row['role_name']);
$session_is_admin = isset($row['role_is_admin']) && $row['role_is_admin'] == 1;
$session_user_config_force_mfa = intval($row['user_config_force_mfa']);
$user_config_records_per_page = intval($row['user_config_records_per_page']);
$user_config_theme_dark = intval($row['user_config_theme_dark']);

// Check user type is agent aka 1
if ($session_user_type !== 1) {
    session_unset();
    session_destroy();
    redirect("/login.php");
}

// Check User is active
if ($session_user_status !== 1) {
    session_unset();
    session_destroy();
    redirect("/login.php");
}

// Check User is archived
if ($session_user_archived_at !== null) {
    session_unset();
    session_destroy();
    redirect("/login.php");
}

// Load user client permissions
$user_client_access_sql = "SELECT client_id FROM user_client_permissions WHERE user_id = $session_user_id";
$user_client_access_result = mysqli_query($mysqli, $user_client_access_sql);

$client_access_array = [];
while ($row = mysqli_fetch_assoc($user_client_access_result)) {
    $client_access_array[] = $row['client_id'];
}

$client_access_string = implode(',', $client_access_array);
$access_permission_query = "";
if ($client_access_string && !$session_is_admin) {
    $access_permission_query = "AND clients.client_id IN ($client_access_string)";
}

// Phase 15: legacy file encryption — first-login migration redirect.
// If this user has plaintext files left to encrypt AND the vault is
// unlocked AND we're on a normal page (not an AJAX/form/migration URL),
// send them to the migration UI. Once the sweep is complete for every
// client this user can access, the redirect stops firing and normal
// navigation resumes.
require_once __DIR__ . '/legacy_file_sweeper.php';
require_once __DIR__ . '/vault_unlock.php';

$_request_uri      = $_SERVER['REQUEST_URI'] ?? '';
$_is_migration_url = strpos($_request_uri, '/agent/migrate_legacy_files') === 0;
$_is_xhr           = ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'XMLHttpRequest';
$_is_form_or_ajax  = (bool) preg_match('#^/agent/(post|ajax)\.php#', $_request_uri);
$_skip_redirect    = $_is_migration_url || $_is_xhr || $_is_form_or_ajax;

// Only admins drive the migration. Their per-user grant covers every
// client master, so the sweep makes uniform progress. Non-admins might
// hit grant gaps mid-sweep (per-user keypair compartmentalisation),
// which would stall the progress bar; they're better off just navigating
// normally while the admin completes the migration.
if (!$_skip_redirect && $session_is_admin) {
    // Cheap check: any plaintext files left? Skips redirect if the vault
    // is locked — the user is heading to vault_unlock already in that
    // case, or has no PIN/PRF method enrolled.
    $_vault_master = vaultMasterKeyFromSession();
    if ($_vault_master !== null) {
        sodium_memzero($_vault_master);
        $_pending = legacyFilesPendingForUser($mysqli, $session_user_id, $session_is_admin);
        if ($_pending > 0) {
            header('Location: /agent/migrate_legacy_files.php');
            exit;
        }
    }
}
