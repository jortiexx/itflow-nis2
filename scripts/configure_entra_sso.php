#!/usr/bin/env php
<?php
/*
 * One-shot Entra SSO config injector.
 *
 * Use after registering an app in Entra and copying out:
 *   - Directory (tenant) ID
 *   - Application (client) ID
 *   - Client secret value
 *
 * Usage:
 *   php scripts/configure_entra_sso.php <tenant_id> <client_id> <client_secret> [redirect_uri]
 *
 * Defaults:
 *   redirect_uri = http://localhost/agent/login_entra_callback.php
 *
 * The script:
 *   - Validates tenant_id and client_id are GUIDs
 *   - Updates settings table with all SSO fields
 *   - Sets config_agent_sso_enabled = 1
 *   - Leaves JIT provisioning OFF for safety
 *   - Prints the redirect URI you must register in Entra
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}
if ($argc < 4) {
    fwrite(STDERR, "Usage: php configure_entra_sso.php <tenant_id> <client_id> <client_secret> [redirect_uri]\n");
    fwrite(STDERR, "Default redirect_uri: http://localhost/agent/login_entra_callback.php\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once 'config.php';
require_once 'functions.php';

$tenant_id     = trim($argv[1]);
$client_id     = trim($argv[2]);
$client_secret = $argv[3];
$redirect_uri  = $argv[4] ?? 'http://localhost/agent/login_entra_callback.php';

$guid = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';
if (!preg_match($guid, $tenant_id)) {
    fwrite(STDERR, "tenant_id must be a GUID\n");
    exit(2);
}
if (!preg_match($guid, $client_id)) {
    fwrite(STDERR, "client_id must be a GUID\n");
    exit(2);
}
if (strlen($client_secret) < 10) {
    fwrite(STDERR, "client_secret looks too short — did you paste the Secret ID instead of the Value?\n");
    exit(2);
}
if (!preg_match('#^https?://#', $redirect_uri)) {
    fwrite(STDERR, "redirect_uri must be an absolute http(s) URL\n");
    exit(2);
}

$tenant_e = mysqli_real_escape_string($mysqli, $tenant_id);
$client_e = mysqli_real_escape_string($mysqli, $client_id);
$secret_e = mysqli_real_escape_string($mysqli, $client_secret);
$redir_e  = mysqli_real_escape_string($mysqli, $redirect_uri);

$ok = mysqli_query($mysqli, "
    UPDATE settings
    SET config_agent_sso_enabled = 1,
        config_agent_sso_tenant_id = '$tenant_e',
        config_agent_sso_client_id = '$client_e',
        config_agent_sso_client_secret = '$secret_e',
        config_agent_sso_redirect_uri = '$redir_e',
        config_agent_sso_jit_provisioning = 0
    WHERE company_id = 1
");

if (!$ok) {
    fwrite(STDERR, "DB update failed: " . mysqli_error($mysqli) . "\n");
    exit(3);
}

echo "OK. Agent SSO is now configured and enabled.\n\n";
echo "Tenant ID:    $tenant_id\n";
echo "Client ID:    $client_id\n";
echo "Redirect URI: $redirect_uri\n";
echo "Secret:       (stored, " . strlen($client_secret) . " chars)\n";
echo "\n";
echo "Make sure your Entra app registration has this redirect URI configured\n";
echo "exactly as shown above (Web platform). Then:\n";
echo "  1. Log out of ITFlow.\n";
echo "  2. On the login page, click 'Sign in with Microsoft'.\n";
echo "  3. Complete the Entra prompt.\n";
echo "  4. You should land back on ITFlow signed in as your matched agent.\n";
