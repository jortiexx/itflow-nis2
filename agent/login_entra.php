<?php
/*
 * Agent SSO — Microsoft Entra ID OIDC, initiation step.
 *
 * Generates state, nonce, and PKCE pair; stores them in the session;
 * redirects the browser to the Entra authorization endpoint.
 *
 * The callback is handled by agent/login_entra_callback.php.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/entra_sso.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');
    if ($config_https_only) {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

$row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT config_agent_sso_enabled,
            config_agent_sso_tenant_id,
            config_agent_sso_client_id,
            config_agent_sso_redirect_uri
     FROM settings
     WHERE company_id = 1
     LIMIT 1"
));

if (!$row || empty($row['config_agent_sso_enabled'])) {
    http_response_code(404);
    die('Agent SSO is not enabled.');
}

$tenant_id    = trim($row['config_agent_sso_tenant_id'] ?? '');
$client_id    = trim($row['config_agent_sso_client_id'] ?? '');
$redirect_uri = trim($row['config_agent_sso_redirect_uri'] ?? '');

if ($tenant_id === '' || $client_id === '' || $redirect_uri === '') {
    http_response_code(500);
    die('Agent SSO is not fully configured.');
}

$state = bin2hex(random_bytes(16));
$nonce = bin2hex(random_bytes(16));
$pkce  = entraGeneratePkcePair();

$_SESSION['agent_sso_pending'] = [
    'state'         => $state,
    'nonce'         => $nonce,
    'pkce_verifier' => $pkce['verifier'],
    'created'       => time(),
];

$auth_url = entraAuthorizationUrl($tenant_id, $client_id, $redirect_uri, $state, $nonce, $pkce['challenge']);

header('Location: ' . $auth_url, true, 302);
exit;
