<?php
/*
 * WebAuthn registration — step 2: verify the navigator.credentials.create()
 * response and store the credential.
 */

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
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit;
}
if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
    http_response_code(403);
    echo json_encode(['error' => 'CSRF token mismatch']);
    exit;
}
if (empty($_SESSION['webauthn_register_challenge'])) {
    http_response_code(400);
    echo json_encode(['error' => 'no pending registration challenge']);
    exit;
}

$user_id   = intval($_SESSION['user_id']);
$challenge = $_SESSION['webauthn_register_challenge'];
unset($_SESSION['webauthn_register_challenge']);

$payload = json_decode($_POST['credential'] ?? '', true);
if (!is_array($payload)) {
    http_response_code(400);
    echo json_encode(['error' => 'invalid credential payload']);
    exit;
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
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

$credential_id_b64 = webauthnB64UrlEncode($reg['credential_id']);
$pem               = $reg['public_key_pem'];
$alg               = intval($reg['alg']);
$sign_count        = intval($reg['sign_count']);
$label             = trim((string)($_POST['label'] ?? '')) ?: 'Security key';
$label = substr($label, 0, 100);

$cred_id_e = mysqli_real_escape_string($mysqli, $credential_id_b64);
$pem_e     = mysqli_real_escape_string($mysqli, $pem);
$label_e   = mysqli_real_escape_string($mysqli, $label);

$ok = mysqli_query($mysqli, "
    INSERT INTO user_webauthn_credentials
    SET user_id = $user_id,
        credential_id = '$cred_id_e',
        public_key_pem = '$pem_e',
        cose_alg = $alg,
        sign_count = $sign_count,
        label = '$label_e',
        created_at = NOW()
");

if (!$ok) {
    http_response_code(500);
    echo json_encode(['error' => 'could not store credential']);
    exit;
}

logAction('User Account', 'WebAuthn registered', "$session_name registered a WebAuthn credential ($label)", 0, $user_id);
securityAudit('webauthn.credential.created', [
    'user_id'   => $user_id,
    'target_id' => intval(mysqli_insert_id($mysqli)),
    'metadata'  => ['label' => $label, 'alg' => $alg],
]);

echo json_encode(['ok' => true]);
