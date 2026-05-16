<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_agent_sso_settings'])) {

    validateAdminRole();
    validateCSRFToken($_POST['csrf_token'] ?? '');

    $enabled                = !empty($_POST['agent_sso_enabled']) ? 1 : 0;
    $tenant_id              = trim($_POST['agent_sso_tenant_id'] ?? '');
    $sso_client_id          = trim($_POST['agent_sso_client_id'] ?? '');
    $new_secret             = $_POST['agent_sso_client_secret'] ?? '';
    $redirect_uri           = trim($_POST['agent_sso_redirect_uri'] ?? '');
    $jit_provisioning       = !empty($_POST['agent_sso_jit_provisioning']) ? 1 : 0;
    $default_role_id        = intval($_POST['agent_sso_default_role_id'] ?? 0);
    $jit_required_group_id  = trim($_POST['agent_sso_jit_required_group_id'] ?? '');

    // Reject obviously bogus tenant / client GUIDs to fail fast.
    $guid_re = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';
    if ($enabled) {
        if (!preg_match($guid_re, $tenant_id)) {
            flash_alert('Tenant ID must be a valid GUID.', 'danger');
            redirect();
        }
        if (!preg_match($guid_re, $sso_client_id)) {
            flash_alert('Client ID must be a valid GUID.', 'danger');
            redirect();
        }
        if (!preg_match('#^https?://#', $redirect_uri)) {
            flash_alert('Redirect URI must be an absolute http(s) URL.', 'danger');
            redirect();
        }
        if ($jit_provisioning && $default_role_id === 0) {
            flash_alert('JIT provisioning requires a default role.', 'danger');
            redirect();
        }
        if ($jit_required_group_id !== '' && !preg_match($guid_re, $jit_required_group_id)) {
            flash_alert('JIT required group ID must be a valid GUID (or empty to disable group gating).', 'danger');
            redirect();
        }
    }

    $tenant_id_e          = mysqli_real_escape_string($mysqli, $tenant_id);
    $sso_client_id_e      = mysqli_real_escape_string($mysqli, $sso_client_id);
    $redirect_uri_e       = mysqli_real_escape_string($mysqli, $redirect_uri);
    $jit_group_id_clause  = ($jit_required_group_id === '')
        ? 'NULL'
        : "'" . mysqli_real_escape_string($mysqli, $jit_required_group_id) . "'";

    $secret_clause = '';
    if ($new_secret !== '') {
        $secret_e = mysqli_real_escape_string($mysqli, $new_secret);
        $secret_clause = ", config_agent_sso_client_secret = '$secret_e'";
    }

    mysqli_query($mysqli, "
        UPDATE settings
        SET config_agent_sso_enabled              = $enabled,
            config_agent_sso_tenant_id            = '$tenant_id_e',
            config_agent_sso_client_id            = '$sso_client_id_e',
            config_agent_sso_redirect_uri         = '$redirect_uri_e',
            config_agent_sso_jit_provisioning     = $jit_provisioning,
            config_agent_sso_default_role_id      = $default_role_id,
            config_agent_sso_jit_required_group_id = $jit_group_id_clause
            $secret_clause
        WHERE company_id = 1
    ");

    logAction('Settings', 'Edit', "$session_name updated agent SSO settings (enabled=$enabled)");

    flash_alert('Agent SSO settings saved');
    redirect();
}
