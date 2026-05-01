<?php
/*
 * Login WebAuthn — verify the assertion and complete login.
 *
 * This endpoint mirrors the post-MFA branch of login.php for the agent
 * flow: it consumes pending_mfa_login, regenerates the session id,
 * sets up the session encryption material, logs the event, and returns
 * a redirect URL.
 */

ob_start();

require_once 'config.php';
require_once 'functions.php';
require_once 'includes/security_headers.php';
require_once 'includes/webauthn.php';
require_once 'includes/security_audit.php';
require_once 'includes/load_global_settings.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

ob_end_clean();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}

$pending = $_SESSION['pending_mfa_login'] ?? null;
if (!$pending || empty($pending['agent_user_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'no pending login']);
    exit;
}
if (empty($_SESSION['webauthn_login_challenge'])) {
    http_response_code(400);
    echo json_encode(['error' => 'no pending challenge']);
    exit;
}

$user_id   = intval($pending['agent_user_id']);
$challenge = $_SESSION['webauthn_login_challenge'];
unset($_SESSION['webauthn_login_challenge']);

$payload = json_decode($_POST['credential'] ?? '', true);
if (!is_array($payload) || empty($payload['id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid credential payload']);
    exit;
}

$cred_id_b64 = (string)$payload['id'];
$cred_id_e   = mysqli_real_escape_string($mysqli, $cred_id_b64);

$cred_row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT cred_id, user_id, public_key_pem, cose_alg, sign_count, label
    FROM user_webauthn_credentials
    WHERE credential_id = '$cred_id_e' AND user_id = $user_id
    LIMIT 1
"));
if (!$cred_row) {
    http_response_code(400);
    echo json_encode(['error' => 'unknown credential']);
    exit;
}

$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);
$origin = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
) ? "https://{$_SERVER['HTTP_HOST']}" : "http://{$_SERVER['HTTP_HOST']}";

try {
    $new_count = webauthnVerifyAssertion(
        $payload,
        $cred_row['public_key_pem'],
        intval($cred_row['sign_count']),
        intval($cred_row['cose_alg']),
        $challenge,
        $origin,
        $rp_id
    );
} catch (WebAuthnException $e) {
    logAction('Login', 'MFA Failed', "WebAuthn assertion failed for user_id=$user_id", 0, $user_id);
    securityAudit('login.mfa.failed', [
        'user_id'  => $user_id,
        'metadata' => ['method' => 'webauthn', 'reason' => $e->getMessage()],
    ]);
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

// Update sign counter
$cred_db_id = intval($cred_row['cred_id']);
mysqli_query($mysqli, "
    UPDATE user_webauthn_credentials
    SET sign_count = $new_count, last_used_at = NOW()
    WHERE cred_id = $cred_db_id
");

// Promote pending session to fully logged in (mirrors login.php success branch)
$row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT user_name, user_email FROM users WHERE user_id = $user_id LIMIT 1
"));
$user_name  = $row ? sanitizeInput($row['user_name'])  : 'agent';
$user_email = $row ? sanitizeInput($row['user_email']) : '';

session_regenerate_id(true);

$_SESSION['user_id']    = $user_id;
$_SESSION['csrf_token'] = randomString(32);
$_SESSION['logged']     = true;

if (!empty($pending['agent_master_key'])) {
    generateUserSessionKey($pending['agent_master_key']);
    // Phase 18: WebAuthn 2FA confirms identity → step-up fresh.
    $_SESSION['vault_unlocked']    = true;
    $_SESSION['vault_unlocked_at'] = time();
    $_SESSION['vault_step_up_at']  = time();
}
if (!empty($pending['agent_privkey'])) {
    pushUserPrivkeyToSession($pending['agent_privkey']);
}

unset($_SESSION['pending_mfa_login']);
unset($_SESSION['pending_dual_login']);

$session_user_id = $user_id;
logAction('Login', 'Success', "$user_name signed in with WebAuthn 2FA", 0, $user_id);
securityAudit('login.password.success', [
    'user_id'  => $user_id,
    'metadata' => ['mfa' => 'webauthn'],
]);

$start = $config_start_page ?? 'clients.php';
echo json_encode(['ok' => true, 'redirect' => "/agent/$start"]);
