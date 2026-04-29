<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

require_once __DIR__ . '/../../includes/security_audit.php';

if (isset($_POST['save_audit_retention'])) {

    validateAdminRole();
    validateCSRFToken($_POST['csrf_token'] ?? '');

    $days = intval($_POST['audit_retention_days'] ?? 365);
    if ($days < 0)      $days = 0;
    if ($days > 36500)  $days = 36500;

    mysqli_query(
        $mysqli,
        "UPDATE settings SET config_security_audit_retention_days = $days WHERE company_id = 1"
    );

    logAction('Settings', 'Edit', "$session_name set audit retention to $days days");
    securityAudit('settings.audit_retention.updated', [
        'user_id'  => $session_user_id,
        'metadata' => ['days' => $days],
    ]);

    flash_alert("Audit retention updated to $days days.");
    redirect();
}
