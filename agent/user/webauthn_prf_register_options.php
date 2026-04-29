<?php
/*
 * Vault PRF enrollment — step 1: issue PublicKeyCredentialCreationOptions
 * with the PRF extension. The vault-prf-enroll.js helper consumes the JSON
 * and calls navigator.credentials.create().
 *
 * Vault must already be unlocked (master key in session) — we wrap the
 * master key under the new PRF-derived KEK during the verify step.
 */

ob_start();

require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../../functions.php';
require_once __DIR__ . '/../../includes/check_login.php';
require_once __DIR__ . '/../../includes/webauthn.php';
require_once __DIR__ . '/../../includes/vault_unlock.php';

ob_end_clean();
header('Content-Type: application/json');

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'not authenticated']));
}
if (vaultMasterKeyFromSession() === null) {
    http_response_code(400);
    exit(json_encode(['error' => 'vault is locked; sign in with password (or unlock with PIN) first']));
}

$user_id    = intval($_SESSION['user_id']);
$user_name  = (string)($session_name ?? "user_$user_id");
$user_email = (string)($session_email ?? "user_$user_id");

$challenge = random_bytes(32);
$prf_salt  = random_bytes(32);
$_SESSION['vault_prf_register_challenge'] = $challenge;
$_SESSION['vault_prf_register_salt']      = $prf_salt;

$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);

// Existing PRF credentials should be excluded so the same hardware key is
// not enrolled twice (which would silently overwrite the wrapped key).
$existing = [];
$rs = mysqli_query($mysqli,
    "SELECT credential_id FROM user_vault_unlock_methods
     WHERE user_id = $user_id AND method_type = 'webauthn_prf'");
if ($rs) {
    while ($row = mysqli_fetch_assoc($rs)) {
        $existing[] = ['type' => 'public-key', 'id' => $row['credential_id']];
    }
}

echo json_encode([
    'challenge' => webauthnB64UrlEncode($challenge),
    'rp'        => ['name' => 'ITFlow', 'id' => $rp_id],
    'user'      => [
        'id'          => webauthnB64UrlEncode(pack('N', $user_id)),
        'name'        => $user_email,
        'displayName' => $user_name,
    ],
    'pubKeyCredParams' => [
        ['type' => 'public-key', 'alg' => -7],   // ES256
        ['type' => 'public-key', 'alg' => -257], // RS256
    ],
    'authenticatorSelection' => [
        'userVerification' => 'required',
        'residentKey'      => 'preferred',
    ],
    'attestation'       => 'none',
    'timeout'           => 60000,
    'excludeCredentials'=> $existing,
    'extensions' => [
        'prf' => ['eval' => ['first' => webauthnB64UrlEncode($prf_salt)]],
    ],
]);
