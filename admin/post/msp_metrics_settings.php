<?php
/*
 * ITFlow - POST handler for admin/msp_metrics_settings.php
 *
 * System-wide MSP metrics config: feature flag, per-source API URL + key.
 * Bearer keys follow the established fork pattern (plaintext in settings,
 * see config_smtp_password / config_agent_sso_client_secret) — empty form
 * input means "keep existing", same UX pattern.
 */
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_msp_metrics_settings'])) {
    validateCSRFToken($_POST['csrf_token']);

    $enabled        = !empty($_POST['msp_metrics_enabled']) ? 1 : 0;
    $wefact_url     = sanitizeInput($_POST['msp_wefact_api_url']    ?? '');
    $wefact_key_in  = $_POST['msp_wefact_api_key']                  ?? '';
    $timeon_url     = sanitizeInput($_POST['msp_timeon_api_url']    ?? '');
    $timeon_key_in  = $_POST['msp_timeon_api_key']                  ?? '';
    $freshdesk_dom  = sanitizeInput($_POST['msp_freshdesk_domain']  ?? '');
    $freshdesk_key_in = $_POST['msp_freshdesk_api_key']             ?? '';

    // Keep-existing pattern: only overwrite the secret column when the form
    // input is non-empty. The placeholder text in the form is "(unchanged)"
    // so the user knows blank = preserve.
    $clauses = [
        "config_module_enable_msp_metrics = $enabled",
        "config_msp_wefact_api_url    = '" . mysqli_real_escape_string($mysqli, $wefact_url)    . "'",
        "config_msp_timeon_api_url    = '" . mysqli_real_escape_string($mysqli, $timeon_url)    . "'",
        "config_msp_freshdesk_domain  = '" . mysqli_real_escape_string($mysqli, $freshdesk_dom) . "'",
    ];
    if ($wefact_key_in !== '') {
        $clauses[] = "config_msp_wefact_api_key = '" . mysqli_real_escape_string($mysqli, $wefact_key_in) . "'";
    }
    if ($timeon_key_in !== '') {
        $clauses[] = "config_msp_timeon_api_key = '" . mysqli_real_escape_string($mysqli, $timeon_key_in) . "'";
    }
    if ($freshdesk_key_in !== '') {
        $clauses[] = "config_msp_freshdesk_api_key = '" . mysqli_real_escape_string($mysqli, $freshdesk_key_in) . "'";
    }

    mysqli_query($mysqli, "UPDATE settings SET " . implode(", ", $clauses) . " WHERE company_id = 1");

    logAction('MSP Metrics', 'Edit', "$session_name updated MSP metrics settings");
    flash_alert('MSP Metrics settings saved');
    redirect('msp_metrics_settings.php');
}
