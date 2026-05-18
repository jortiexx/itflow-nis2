<?php
/*
 * Vault unlock via WebAuthn PRF — step 1: issue PublicKeyCredentialRequestOptions.
 * Reachable when the user is authenticated (logged=true) but the vault
 * is still locked, and the user has at least one webauthn_prf method
 * enrolled.
 */

ob_start();

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_headers.php';
require_once __DIR__ . '/../includes/webauthn.php';
require_once __DIR__ . '/../includes/vault_unlock.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

ob_end_clean();
header('Content-Type: application/json');

if (empty($_SESSION['user_id']) || empty($_SESSION['logged'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'not authenticated']));
}

$user_id = intval($_SESSION['user_id']);

$rs = mysqli_query($mysqli,
    "SELECT credential_id, prf_salt, transports
     FROM user_vault_unlock_methods
     WHERE user_id = $user_id AND method_type = 'webauthn_prf'
       AND disabled_at IS NULL
       AND (locked_until IS NULL OR locked_until <= NOW())");
$creds = [];
$prf_salt_b64 = null;
if ($rs) {
    while ($row = mysqli_fetch_assoc($rs)) {
        // Pass transports so the browser knows whether to surface the
        // platform authenticator (Windows Hello / Touch ID) rather than
        // showing the generic "security key / phone" picker. Without this
        // hint Edge/Chrome on Windows offers cross-device options that
        // the user cannot complete.
        $entry = ['type' => 'public-key', 'id' => $row['credential_id']];
        if (!empty($row['transports'])) {
            $entry['transports'] = array_values(array_filter(array_map('trim', explode(',', $row['transports']))));
        }
        $creds[] = $entry;
    }
}
if (empty($creds)) {
    http_response_code(400);
    exit(json_encode(['error' => 'no hardware unlock methods enrolled']));
}

// Use evalByCredential so each enrolled credential gets its own PRF salt.
// This is the WebAuthn-2 spec mechanism for per-credential PRF inputs.
$eval_by_credential = [];
$salts_by_cred      = []; // server-side cache for verify step
$rs = mysqli_query($mysqli,
    "SELECT credential_id, prf_salt
     FROM user_vault_unlock_methods
     WHERE user_id = $user_id AND method_type = 'webauthn_prf'
       AND disabled_at IS NULL");
if ($rs) {
    while ($row = mysqli_fetch_assoc($rs)) {
        $eval_by_credential[$row['credential_id']] = ['first' => $row['prf_salt']];
        $salts_by_cred[$row['credential_id']]      = $row['prf_salt'];
    }
}

$challenge = random_bytes(32);
$_SESSION['vault_prf_unlock_challenge']     = $challenge;
$_SESSION['vault_prf_unlock_salts_by_cred'] = $salts_by_cred;

$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);

echo json_encode([
    'challenge'        => webauthnB64UrlEncode($challenge),
    'rpId'             => $rp_id,
    'allowCredentials' => $creds,
    'userVerification' => 'required',
    'timeout'          => 60000,
    // Hint the browser to use the platform authenticator first. Mirrors the
    // enrolment options — without this, the Windows "Choose a passkey"
    // picker can suggest cross-device options that don't match the
    // platform-bound credential and shows "no passkeys available".
    'hints' => ['client-device'],
    'extensions' => [
        'prf' => [
            // evalByCredential: keys are credential ids (base64url), values are
            // {first: <salt>} pairs. Browser supplies the matching salt to the
            // chosen authenticator.
            'evalByCredential' => $eval_by_credential,
        ],
    ],
]);
