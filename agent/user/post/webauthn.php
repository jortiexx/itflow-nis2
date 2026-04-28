<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once __DIR__ . '/../../../includes/security_audit.php';

if (isset($_POST['delete_webauthn_credential'])) {

    validateCSRFToken($_POST['csrf_token'] ?? '');

    $cred_id = intval($_POST['cred_id'] ?? 0);
    if ($cred_id <= 0) {
        flash_alert('Invalid credential id.', 'danger');
        redirect();
    }

    mysqli_query($mysqli, "
        DELETE FROM user_webauthn_credentials
        WHERE cred_id = $cred_id AND user_id = $session_user_id
    ");

    if (mysqli_affected_rows($mysqli) > 0) {
        logAction('User Account', 'WebAuthn removed', "$session_name removed a WebAuthn credential", 0, $session_user_id);
        securityAudit('webauthn.credential.removed', [
            'user_id'   => $session_user_id,
            'target_id' => $cred_id,
        ]);
        flash_alert('Security key removed.');
    } else {
        flash_alert('Credential not found.', 'danger');
    }
    redirect();
}
