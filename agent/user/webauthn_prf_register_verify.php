<?php
/*
 * Vault PRF enrollment — step 2: verify the registration response and the
 * PRF output, then wrap the master key under the PRF-derived KEK and store
 * a webauthn_prf row in user_vault_unlock_methods.
 *
 * The browser must include the PRF result from
 * `cred.getClientExtensionResults().prf.results.first` in the POST body
 * as `prf_output` (base64url). If the authenticator does not support PRF
 * eval at registration time the field will be missing and we reject with
 * a clear message.
 */

ob_start();

require_once __DIR__ . '/../../config.php';
require_once __DIR__ . '/../../functions.php';
require_once __DIR__ . '/../../includes/check_login.php';
require_once __DIR__ . '/../../includes/webauthn.php';
require_once __DIR__ . '/../../includes/vault_unlock.php';
require_once __DIR__ . '/../../includes/security_audit.php';

ob_end_clean();
header('Content-Type: application/json');

if (empty($_SESSION['user_id']) || $_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(400);
    exit(json_encode(['error' => 'bad request']));
}
if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    exit(json_encode(['error' => 'CSRF token mismatch']));
}

$challenge = $_SESSION['vault_prf_register_challenge'] ?? null;
$prf_salt  = $_SESSION['vault_prf_register_salt']      ?? null;
unset($_SESSION['vault_prf_register_challenge'], $_SESSION['vault_prf_register_salt']);

if (!$challenge || !$prf_salt) {
    http_response_code(400);
    exit(json_encode(['error' => 'no pending registration']));
}

$payload        = json_decode($_POST['credential'] ?? '', true);
$prf_output_b64 = (string)($_POST['prf_output'] ?? '');
$label          = trim((string)($_POST['label'] ?? ''));

if (!is_array($payload)) {
    http_response_code(400);
    exit(json_encode(['error' => 'invalid credential payload']));
}
if ($prf_output_b64 === '') {
    http_response_code(400);
    exit(json_encode(['error' => 'authenticator did not return a PRF output — your security key may not support the WebAuthn PRF extension']));
}

$rp_id = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST']);
$origin = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
) ? "https://{$_SERVER['HTTP_HOST']}" : "http://{$_SERVER['HTTP_HOST']}";

try {
    $reg = webauthnVerifyRegistration($payload, $challenge, $origin, $rp_id);
} catch (WebAuthnException $e) {
    http_response_code(400);
    exit(json_encode(['error' => $e->getMessage()]));
}

try {
    $prf_output = webauthnB64UrlDecode($prf_output_b64);
} catch (Throwable $e) {
    http_response_code(400);
    exit(json_encode(['error' => 'invalid prf_output encoding']));
}
if (strlen($prf_output) !== 32) {
    http_response_code(400);
    exit(json_encode(['error' => 'PRF output must be 32 bytes (got ' . strlen($prf_output) . ')']));
}

$master = vaultMasterKeyFromSession();
if ($master === null) {
    http_response_code(400);
    exit(json_encode(['error' => 'vault locked while enrolling']));
}

$user_id    = intval($_SESSION['user_id']);
$cred_id    = webauthnB64UrlEncode($reg['credential_id']);

try {
    $method_id = vaultStorePrfMethod(
        $user_id,
        $master,
        $prf_output,
        $cred_id,
        $reg['public_key_pem'],
        intval($reg['alg']),
        intval($reg['sign_count']),
        $prf_salt,
        $label,
        $mysqli
    );
} catch (Throwable $e) {
    error_log('vault PRF enroll insert failed: ' . $e->getMessage());
    http_response_code(500);
    exit(json_encode(['error' => 'could not store PRF method']));
}

logAction('Vault', 'PRF method registered', "$session_name registered a hardware vault unlock method", 0, $user_id);
securityAudit('vault.method.created', [
    'user_id'   => $user_id,
    'target_id' => $method_id,
    'metadata'  => ['method_type' => 'webauthn_prf', 'label' => $label, 'alg' => intval($reg['alg'])],
]);

echo json_encode(['ok' => true, 'method_id' => $method_id]);
