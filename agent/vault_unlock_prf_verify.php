<?php
/*
 * Vault unlock via WebAuthn PRF — step 2: verify the assertion signature
 * (proves the legitimate authenticator was used) and use the supplied
 * PRF output to unwrap the master key.
 *
 * The PRF output itself is not separately verifiable on the server side
 * (it's derived inside the authenticator). Trust comes from:
 *  - The assertion signature, which proves the matching credential was used
 *  - The wrapping authentication tag (AES-256-GCM), which fails decryption
 *    if the PRF output is wrong by even one bit
 */

ob_start();

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_headers.php';
require_once __DIR__ . '/../includes/webauthn.php';
require_once __DIR__ . '/../includes/vault_unlock.php';
require_once __DIR__ . '/../includes/rate_limit.php';
require_once __DIR__ . '/../includes/security_audit.php';
require_once __DIR__ . '/../includes/load_global_settings.php';

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
    exit(json_encode(['error' => 'POST required']));
}
if (empty($_SESSION['user_id']) || empty($_SESSION['logged'])) {
    http_response_code(401);
    exit(json_encode(['error' => 'not authenticated']));
}

$user_id   = intval($_SESSION['user_id']);
$challenge = $_SESSION['vault_prf_unlock_challenge']    ?? null;
$salts_map = $_SESSION['vault_prf_unlock_salts_by_cred'] ?? null;
unset($_SESSION['vault_prf_unlock_challenge'], $_SESSION['vault_prf_unlock_salts_by_cred']);

if (!$challenge) {
    http_response_code(400);
    exit(json_encode(['error' => 'no pending challenge']));
}

$session_ip = mysqli_real_escape_string($mysqli, sanitizeInput(getIP()));
rateLimitCheckScope('vault', $mysqli);

$payload        = json_decode($_POST['credential'] ?? '', true);
$prf_output_b64 = (string)($_POST['prf_output'] ?? '');

if (!is_array($payload) || empty($payload['id']) || $prf_output_b64 === '') {
    http_response_code(400);
    exit(json_encode(['error' => 'missing credential or prf_output']));
}

$cred_id_b64 = (string)$payload['id'];

$method = vaultFindPrfMethodByCredentialId($user_id, $cred_id_b64, $mysqli);
if (!$method) {
    http_response_code(400);
    exit(json_encode(['error' => 'unknown credential']));
}
if (!empty($method['locked_until']) && strtotime($method['locked_until']) > time()) {
    http_response_code(429);
    exit(json_encode(['error' => 'this hardware unlock method is temporarily locked due to repeated failures']));
}

// Read the public-key PEM and COSE alg to verify the assertion.
$cose_alg = COSE_ALG_ES256;
$row = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT public_key, sign_count FROM user_vault_unlock_methods
     WHERE method_id = " . intval($method['method_id']) . " LIMIT 1"));
if (!$row) {
    http_response_code(400);
    exit(json_encode(['error' => 'method row vanished']));
}
$public_key_pem = $row['public_key'];
$sign_count     = intval($row['sign_count']);

// We didn't store cose_alg in user_vault_unlock_methods for PRF (yet).
// Detect from PEM header heuristically; ES256 PEMs are ~178 chars vs RS256 ~451+.
// More robust: try ES256 first, fall back to RS256 — openssl_verify accepts both
// against the same PEM only if it actually matches the algorithm.
$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);
$origin = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
) ? "https://{$_SERVER['HTTP_HOST']}" : "http://{$_SERVER['HTTP_HOST']}";

$assertion_ok = false;
$new_count    = $sign_count;
foreach ([COSE_ALG_ES256, COSE_ALG_RS256] as $try_alg) {
    try {
        $new_count = webauthnVerifyAssertion(
            $payload, $public_key_pem, $sign_count, $try_alg,
            $challenge, $origin, $rp_id
        );
        $cose_alg     = $try_alg;
        $assertion_ok = true;
        break;
    } catch (WebAuthnException $e) {
        // try the other algorithm
    }
}

if (!$assertion_ok) {
    logAction('Vault', 'Unlock failed', "WebAuthn PRF assertion failed for user_id=$user_id", 0, $user_id);
    securityAudit('vault.unlock.failed', [
        'user_id' => $user_id, 'metadata' => ['method' => 'webauthn_prf', 'reason' => 'assertion'],
    ]);
    http_response_code(400);
    exit(json_encode(['error' => 'assertion verification failed']));
}

// Decode PRF output
try {
    $prf_output = webauthnB64UrlDecode($prf_output_b64);
} catch (Throwable $e) {
    http_response_code(400);
    exit(json_encode(['error' => 'invalid prf_output encoding']));
}

$unlock = vaultUnlockWithPrf(intval($method['method_id']), $prf_output, $mysqli);
if ($unlock === null) {
    logAction('Vault', 'Unlock failed', "WebAuthn PRF unwrap failed for user_id=$user_id", 0, $user_id);
    securityAudit('vault.unlock.failed', [
        'user_id' => $user_id, 'metadata' => ['method' => 'webauthn_prf', 'reason' => 'unwrap'],
    ]);
    http_response_code(400);
    exit(json_encode(['error' => 'unable to unwrap vault with this authenticator']));
}

// Update sign_count (vaultUnlockWithPrf already reset failed_attempts/last_used_at).
$mid = intval($method['method_id']);
mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
    SET sign_count = $new_count
    WHERE method_id = $mid");

// Establish session encryption material.
session_regenerate_id(true);
generateUserSessionKey($unlock['master']);
if (!empty($unlock['privkey'])) {
    pushUserPrivkeyToSession($unlock['privkey']);
}
$_SESSION['vault_unlocked'] = true;
$_SESSION['csrf_token']     = randomString(32);

$row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT user_name FROM users WHERE user_id = $user_id LIMIT 1"));
$user_name = $row ? $row['user_name'] : "user_$user_id";

logAction('Vault', 'Unlock', "$user_name unlocked vault via WebAuthn PRF", 0, $user_id);
securityAudit('vault.unlock.success', [
    'user_id' => $user_id, 'metadata' => ['method' => 'webauthn_prf'],
]);

$start = $config_start_page ?? 'clients.php';
echo json_encode(['ok' => true, 'redirect' => "/agent/$start"]);
