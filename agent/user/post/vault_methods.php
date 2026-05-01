<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once __DIR__ . '/../../../includes/vault_unlock.php';
require_once __DIR__ . '/../../../includes/security_audit.php';

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

    // Phase 11: also wrap the user's privkey under the PIN KEK so SSO+PIN
    // unlocks restore the full keypair to the session, preserving phase-10
    // compartmentalisation. Falls back gracefully if privkey is not yet in
    // session (pre-phase-10 user).
    $privkey_for_pin = userPrivkeyFromSession();
    try {
        vaultSetPin($session_user_id, $master, $privkey_for_pin, $pin, $label, $mysqli);
    } catch (Throwable $e) {
        error_log("vault PIN set failed for user $session_user_id: " . $e->getMessage());
        flash_alert('Could not save vault PIN.', 'danger');
        redirect();
    }

    logAction('Vault', 'PIN set', "$session_name set or updated their vault PIN", 0, $session_user_id);
    securityAudit('vault.method.created', [
        'user_id'  => $session_user_id,
        'metadata' => ['method_type' => 'pin'],
    ]);
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
        securityAudit('vault.method.removed', [
            'user_id'   => $session_user_id,
            'target_id' => $method_id,
        ]);
        flash_alert('Vault unlock method removed.');
    } else {
        flash_alert('Method not found.', 'danger');
    }
    redirect();
}

// Phase 18: kill-switch — temporarily disable a method without losing
// the audit row. Re-enable is a separate POST.
if (isset($_POST['disable_vault_method'])) {

    validateCSRFToken($_POST['csrf_token'] ?? '');

    $method_id = intval($_POST['vault_method_id'] ?? 0);
    if ($method_id <= 0) {
        flash_alert('Invalid method id.', 'danger');
        redirect();
    }

    $ok = vaultDisableMethod($method_id, $session_user_id, $session_user_id, $mysqli);
    if ($ok) {
        logAction('Vault', 'Method disabled', "$session_name disabled a vault unlock method", 0, $session_user_id);
        securityAudit('vault.method.disabled', [
            'user_id'   => $session_user_id,
            'target_id' => $method_id,
            'metadata'  => ['actor' => 'self'],
        ]);
        flash_alert('Vault unlock method disabled.');
    } else {
        flash_alert('Method not found or already disabled.', 'danger');
    }
    redirect();
}

if (isset($_POST['enable_vault_method'])) {

    validateCSRFToken($_POST['csrf_token'] ?? '');

    $method_id = intval($_POST['vault_method_id'] ?? 0);
    if ($method_id <= 0) {
        flash_alert('Invalid method id.', 'danger');
        redirect();
    }

    $ok = vaultEnableMethod($method_id, $session_user_id, $mysqli);
    if ($ok) {
        logAction('Vault', 'Method re-enabled', "$session_name re-enabled a vault unlock method", 0, $session_user_id);
        securityAudit('vault.method.enabled', [
            'user_id'   => $session_user_id,
            'target_id' => $method_id,
        ]);
        flash_alert('Vault unlock method re-enabled.');
    } else {
        flash_alert('Method not found.', 'danger');
    }
    redirect();
}
