<?php
/*
 * Login WebAuthn — issue PublicKeyCredentialRequestOptions during MFA step.
 * Reachable only when a pending_mfa_login session exists, meaning the user
 * has already passed password verification.
 */

require_once 'config.php';
require_once 'functions.php';
require_once 'includes/security_headers.php';
require_once 'includes/webauthn.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

header('Content-Type: application/json');

$pending = $_SESSION['pending_mfa_login'] ?? null;
if (!$pending || empty($pending['agent_user_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'no pending login']);
    exit;
}

$user_id = intval($pending['agent_user_id']);

$creds = [];
$rs = mysqli_query($mysqli, "SELECT credential_id FROM user_webauthn_credentials WHERE user_id = $user_id");
if ($rs) {
    while ($row = mysqli_fetch_assoc($rs)) {
        $creds[] = ['type' => 'public-key', 'id' => $row['credential_id']];
    }
}
if (empty($creds)) {
    http_response_code(400);
    echo json_encode(['error' => 'no security keys enrolled']);
    exit;
}

$challenge = random_bytes(32);
$_SESSION['webauthn_login_challenge'] = $challenge;

$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);

echo json_encode([
    'challenge'        => webauthnB64UrlEncode($challenge),
    'rpId'             => $rp_id,
    'allowCredentials' => $creds,
    'userVerification' => 'required',
    'timeout'          => 60000,
]);
