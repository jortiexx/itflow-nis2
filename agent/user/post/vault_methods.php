<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once __DIR__ . '/../../../includes/vault_unlock.php';

if (isset($_POST['set_vault_pin'])) {

    validateCSRFToken($_POST['csrf_token'] ?? '');

    $pin       = (string)($_POST['vault_pin'] ?? '');
    $confirm   = (string)($_POST['vault_pin_confirm'] ?? '');
    $label     = trim((string)($_POST['vault_pin_label'] ?? ''));

    if ($pin !== $confirm) {
        flash_alert('PINs do not match.', 'danger');
        redirect();
    }

    if (strlen($pin) < VAULT_PIN_MIN_LENGTH) {
        flash_alert('PIN is too short (minimum ' . VAULT_PIN_MIN_LENGTH . ' characters).', 'danger');
        redirect();
    }

    $master = vaultMasterKeyFromSession();
    if ($master === null) {
        flash_alert('Vault is locked. Sign in with your account password to set a vault PIN.', 'danger');
        redirect();
    }

    try {
        vaultSetPin($session_user_id, $master, $pin, $label, $mysqli);
    } catch (Throwable $e) {
        error_log("vault PIN set failed for user $session_user_id: " . $e->getMessage());
        flash_alert('Could not save vault PIN.', 'danger');
        redirect();
    }

    logAction('Vault', 'PIN set', "$session_name set or updated their vault PIN", 0, $session_user_id);
    flash_alert('Vault PIN saved.');
    redirect();
}

if (isset($_POST['delete_vault_method'])) {

    validateCSRFToken($_POST['csrf_token'] ?? '');

    $method_id = intval($_POST['vault_method_id'] ?? 0);
    if ($method_id <= 0) {
        flash_alert('Invalid method id.', 'danger');
        redirect();
    }

    $deleted = vaultDeleteMethod($method_id, $session_user_id, $mysqli);
    if ($deleted) {
        logAction('Vault', 'Method removed', "$session_name removed a vault unlock method", 0, $session_user_id);
        flash_alert('Vault unlock method removed.');
    } else {
        flash_alert('Method not found.', 'danger');
    }
    redirect();
}
