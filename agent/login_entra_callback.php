<?php
/*
 * Agent SSO — Microsoft Entra ID OIDC, callback step.
 *
 * Verifies state, exchanges authorization code for tokens, validates the
 * ID token (signature + claims), maps the Entra identity to a local
 * agent account, and establishes the agent session.
 *
 * Vault unlock (master-key decryption) is NOT performed here. SSO
 * agents authenticate but their credential vault remains locked until
 * Phase 3 (WebAuthn PRF / vault PIN) is in place.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/entra_sso.php';
require_once __DIR__ . '/../includes/vault_unlock.php';
require_once __DIR__ . '/../includes/load_global_settings.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

require_once __DIR__ . '/../includes/inc_set_timezone.php';

$session_ip         = sanitizeInput(getIP());
$session_user_agent = sanitizeInput($_SERVER['HTTP_USER_AGENT'] ?? '');

function ssoFail(string $reason, string $detail = ''): void
{
    global $session_ip, $session_user_agent;
    unset($_SESSION['agent_sso_pending']);
    logAction('SSO Login', 'Failed', "Agent SSO failed: $reason" . ($detail ? " — $detail" : ''));
    $_SESSION['login_message'] = "Sign-in failed: $reason";
    header('Location: ../login.php');
    exit;
}

// ---- Settings ----
$row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT config_agent_sso_enabled,
            config_agent_sso_tenant_id,
            config_agent_sso_client_id,
            config_agent_sso_client_secret,
            config_agent_sso_redirect_uri,
            config_agent_sso_jit_provisioning,
            config_agent_sso_default_role_id
     FROM settings
     WHERE company_id = 1
     LIMIT 1"
));

if (!$row || empty($row['config_agent_sso_enabled'])) {
    http_response_code(404);
    die('Agent SSO is not enabled.');
}

$tenant_id        = trim($row['config_agent_sso_tenant_id'] ?? '');
$client_id        = trim($row['config_agent_sso_client_id'] ?? '');
$client_secret    = trim($row['config_agent_sso_client_secret'] ?? '');
$redirect_uri     = trim($row['config_agent_sso_redirect_uri'] ?? '');
$jit_provisioning = !empty($row['config_agent_sso_jit_provisioning']);
$default_role_id  = intval($row['config_agent_sso_default_role_id'] ?? 0);

if ($tenant_id === '' || $client_id === '' || $client_secret === '' || $redirect_uri === '') {
    ssoFail('Agent SSO is not fully configured');
}

// ---- Validate request ----
if (isset($_GET['error'])) {
    ssoFail((string)$_GET['error'], (string)($_GET['error_description'] ?? ''));
}

$pending = $_SESSION['agent_sso_pending'] ?? null;
if (!$pending || empty($pending['state']) || empty($pending['nonce']) || empty($pending['pkce_verifier'])) {
    ssoFail('No pending SSO session');
}

if ((time() - intval($pending['created'])) > 600) {
    ssoFail('SSO session expired (more than 10 minutes elapsed)');
}

if (empty($_GET['state']) || empty($_GET['code'])) {
    ssoFail('Missing state or code parameter');
}

if (!hash_equals($pending['state'], (string)$_GET['state'])) {
    ssoFail('State parameter mismatch (possible CSRF)');
}

// ---- Exchange code for tokens ----
try {
    $tokens = entraExchangeCodeForTokens(
        $tenant_id, $client_id, $client_secret, $redirect_uri,
        (string)$_GET['code'], $pending['pkce_verifier']
    );
} catch (EntraSsoException $e) {
    ssoFail('Token exchange failed', $e->getMessage());
}

// ---- Validate ID token ----
try {
    $claims = entraValidateIdToken($tokens['id_token'], $tenant_id, $client_id, $pending['nonce']);
} catch (EntraSsoException $e) {
    ssoFail('ID token validation failed', $e->getMessage());
}

unset($_SESSION['agent_sso_pending']);

$entra_oid   = mysqli_real_escape_string($mysqli, $claims['oid']);
$entra_email = mysqli_real_escape_string($mysqli, strtolower($claims['email'] ?? $claims['preferred_username'] ?? $claims['upn'] ?? ''));
$entra_name  = (string)($claims['name'] ?? $claims['preferred_username'] ?? $claims['email'] ?? $claims['oid']);

// ---- Map to local agent account ----
$user = null;

// 1. Match by oid (immutable)
$sql = mysqli_query($mysqli, "
    SELECT users.*, user_settings.user_config_force_mfa
    FROM users
    LEFT JOIN user_settings ON users.user_id = user_settings.user_id
    WHERE user_entra_oid = '$entra_oid'
      AND user_type = 1
      AND user_status = 1
      AND user_archived_at IS NULL
    LIMIT 1
");
if ($sql && $row = mysqli_fetch_assoc($sql)) {
    $user = $row;
}

// 2. Match by email (and bind oid for next time) if oid not found yet
if (!$user && $entra_email !== '') {
    $sql = mysqli_query($mysqli, "
        SELECT users.*, user_settings.user_config_force_mfa
        FROM users
        LEFT JOIN user_settings ON users.user_id = user_settings.user_id
        WHERE LOWER(user_email) = '$entra_email'
          AND user_type = 1
          AND user_status = 1
          AND user_archived_at IS NULL
          AND (user_entra_oid IS NULL OR user_entra_oid = '')
        LIMIT 1
    ");
    if ($sql && $row = mysqli_fetch_assoc($sql)) {
        $user = $row;
        $bind_uid = intval($user['user_id']);
        mysqli_query($mysqli, "
            UPDATE users
            SET user_entra_oid = '$entra_oid',
                user_auth_method = 'entra'
            WHERE user_id = $bind_uid
        ");
        $user['user_entra_oid']   = $claims['oid'];
        $user['user_auth_method'] = 'entra';
    }
}

// 3. JIT provisioning
if (!$user && $jit_provisioning && $entra_email !== '' && $default_role_id > 0) {
    $name_escaped  = mysqli_real_escape_string($mysqli, $entra_name);
    $email_escaped = $entra_email;
    mysqli_query($mysqli, "
        INSERT INTO users
        SET user_name = '$name_escaped',
            user_email = '$email_escaped',
            user_password = '',
            user_type = 1,
            user_status = 1,
            user_role_id = $default_role_id,
            user_entra_oid = '$entra_oid',
            user_auth_method = 'entra'
    ");
    $new_user_id = mysqli_insert_id($mysqli);
    mysqli_query($mysqli, "INSERT INTO user_settings SET user_id = $new_user_id");

    $sql = mysqli_query($mysqli, "
        SELECT users.*, user_settings.user_config_force_mfa
        FROM users
        LEFT JOIN user_settings ON users.user_id = user_settings.user_id
        WHERE user_id = $new_user_id
        LIMIT 1
    ");
    $user = $sql ? mysqli_fetch_assoc($sql) : null;
    if ($user) {
        logAction('User', 'Create', "JIT-provisioned agent {$user['user_email']} from Entra ID", 0, intval($user['user_id']));
    }
}

if (!$user) {
    ssoFail('No matching agent account', "oid=$entra_oid email=$entra_email");
}

// ---- Establish session ----
session_regenerate_id(true);

$user_id    = intval($user['user_id']);
$user_name  = sanitizeInput($user['user_name']);
$user_email = sanitizeInput($user['user_email']);

$_SESSION['user_id']         = $user_id;
$_SESSION['csrf_token']      = randomString(32);
$_SESSION['logged']          = true;
$_SESSION['login_method']    = 'entra';
$_SESSION['vault_unlocked']  = false;  // Phase 3 will set this to true after WebAuthn / PIN unlock

mysqli_query($mysqli, "
    UPDATE users
    SET user_php_session = '" . session_id() . "'
    WHERE user_id = $user_id
");

$session_user_id = $user_id;
logAction('Login', 'Success', "$user_name signed in via Entra SSO", 0, $user_id);

// If the user has a vault PIN enrolled, force PIN entry before exposing
// any pages that may attempt to decrypt credentials.
if (vaultUserHasMethod($user_id, 'pin', $mysqli)) {
    header('Location: /agent/vault_unlock.php');
    exit;
}

// No vault unlock method enrolled — the user gets a working session but
// the credential vault stays locked until they set up a PIN via the
// password-login flow.
$start_page = $config_start_page ?? 'clients.php';
header("Location: /agent/$start_page");
exit;
