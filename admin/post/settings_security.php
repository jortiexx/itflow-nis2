<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_security_settings'])) {

    validateCSRFToken($_POST['csrf_token']);

    $config_login_message = sanitizeInput($_POST['config_login_message']);
    $config_login_key_required = intval($_POST['config_login_key_required'] ?? 0);
    $config_login_key_secret = sanitizeInput($_POST['config_login_key_secret']);
    $config_login_remember_me_expire = intval($_POST['config_login_remember_me_expire']);
    $config_log_retention = intval($_POST['config_log_retention']);

    // Disallow turning on login key without a secret
    if (empty($config_login_key_secret)) {
        $config_login_key_required = 0;
    }

    // Rate-limit fields. Clamp each to sane bounds so an admin can't
    // accidentally set max=0 (= always blocked) or window=1 (= useless).
    $rl_enabled = intval($_POST['config_ratelimit_enabled'] ?? 0) === 1 ? 1 : 0;
    $rl_login_max      = max(1,  intval($_POST['config_ratelimit_login_max']      ?? 10));
    $rl_login_window   = max(60, intval($_POST['config_ratelimit_login_window']   ?? 600));
    $rl_vault_max      = max(1,  intval($_POST['config_ratelimit_vault_max']      ?? 20));
    $rl_vault_window   = max(60, intval($_POST['config_ratelimit_vault_window']   ?? 600));
    $rl_sso_max        = max(1,  intval($_POST['config_ratelimit_sso_max']        ?? 20));
    $rl_sso_window     = max(60, intval($_POST['config_ratelimit_sso_window']     ?? 600));
    $rl_api_max        = max(1,  intval($_POST['config_ratelimit_api_max']        ?? 30));
    $rl_api_window     = max(60, intval($_POST['config_ratelimit_api_window']     ?? 600));
    $rl_pwreset_max    = max(1,  intval($_POST['config_ratelimit_pwreset_max']    ?? 5));
    $rl_pwreset_window = max(60, intval($_POST['config_ratelimit_pwreset_window'] ?? 3600));

    // Phase 18: vault hardening knobs.
    $vault_idle_ttl     = max(60, intval($_POST['config_vault_idle_ttl_seconds']      ?? 1800));
    $vault_lockout_max  = max(60, intval($_POST['config_vault_lockout_max_seconds']   ?? 3600));
    $require_hw_bound   = intval($_POST['config_require_hardware_bound_authenticators'] ?? 0) === 1 ? 1 : 0;

    mysqli_query($mysqli,
        "UPDATE settings SET
            config_login_message               = '$config_login_message',
            config_login_key_required          = '$config_login_key_required',
            config_login_key_secret            = '$config_login_key_secret',
            config_login_remember_me_expire    = $config_login_remember_me_expire,
            config_log_retention               = $config_log_retention,
            config_ratelimit_enabled           = $rl_enabled,
            config_ratelimit_login_max         = $rl_login_max,
            config_ratelimit_login_window      = $rl_login_window,
            config_ratelimit_vault_max         = $rl_vault_max,
            config_ratelimit_vault_window      = $rl_vault_window,
            config_ratelimit_sso_max           = $rl_sso_max,
            config_ratelimit_sso_window        = $rl_sso_window,
            config_ratelimit_api_max           = $rl_api_max,
            config_ratelimit_api_window        = $rl_api_window,
            config_ratelimit_pwreset_max       = $rl_pwreset_max,
            config_ratelimit_pwreset_window    = $rl_pwreset_window,
            config_vault_idle_ttl_seconds              = $vault_idle_ttl,
            config_vault_lockout_max_seconds           = $vault_lockout_max,
            config_require_hardware_bound_authenticators = $require_hw_bound
         WHERE company_id = 1");

    logAction("Settings", "Edit", "$session_name edited security settings");

    flash_alert("Security settings updated");

    redirect();

}
