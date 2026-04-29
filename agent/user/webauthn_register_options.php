<?php
/*
 * WebAuthn registration — step 1: issue PublicKeyCredentialCreationOptions.
 * Returns JSON consumed by the user_security.php JavaScript that calls
 * navigator.credentials.create().
 */

// Capture any stray output from the include chain (warnings, notices,
// HTML from auth-redirect pages) so the response stays valid JSON.
ob_start();

// check_login.php expects config + functions to be loaded already.
require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../../functions.php';
require_once __DIR__ . '/../../includes/check_login.php';
require_once __DIR__ . '/../../includes/webauthn.php';
require_once __DIR__ . '/../../includes/security_audit.php';

ob_end_clean();
header('Content-Type: application/json');

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'not authenticated']);
    exit;
}

$user_id   = intval($_SESSION['user_id']);
$user_name = (string)($session_name ?? 'agent');
$user_email = (string)($session_email ?? '');

$challenge = random_bytes(32);
$_SESSION['webauthn_register_challenge'] = $challenge;

$rp_id = $_SERVER['HTTP_HOST']; // bare host, no scheme/port
// Strip port if present (RP ID must be a registrable domain or bare host)
$rp_id = preg_replace('/:\d+$/', '', $rp_id);

$existing = [];
$rs = mysqli_query($mysqli, "SELECT credential_id FROM user_webauthn_credentials WHERE user_id = $user_id");
if ($rs) {
    while ($row = mysqli_fetch_assoc($rs)) {
        $existing[] = ['type' => 'public-key', 'id' => $row['credential_id']];
    }
}

echo json_encode([
    'challenge' => webauthnB64UrlEncode($challenge),
    'rp' => [
        'name' => 'ITFlow',
        'id'   => $rp_id,
    ],
    'user' => [
        'id'          => webauthnB64UrlEncode(pack('N', $user_id)),
        'name'        => $user_email !== '' ? $user_email : "user_$user_id",
        'displayName' => $user_name,
    ],
    'pubKeyCredParams' => [
        ['type' => 'public-key', 'alg' => -7],    // ES256
        ['type' => 'public-key', 'alg' => -257],  // RS256
    ],
    'authenticatorSelection' => [
        'userVerification' => 'required',
        'residentKey'      => 'preferred',
    ],
    'attestation' => 'none',
    'timeout'     => 60000,
    'excludeCredentials' => $existing,
]);
