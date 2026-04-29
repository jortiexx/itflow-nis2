#!/usr/bin/env php
<?php
/*
 * Vault enrolment magic-link self-test (offline; no DB).
 *
 * The magic-link flow wraps the master key under an Argon2id KEK derived
 * from a random one-shot token, and unwraps it with the same token at
 * redemption time. We exercise just that crypto round-trip here, not the
 * DB or email plumbing.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/vault_unlock.php';

$failures = 0;
$tests    = 0;
function check(string $label, bool $ok): void
{
    global $failures, $tests;
    $tests++;
    if ($ok) echo "  [PASS] $label\n";
    else { echo "  [FAIL] $label\n"; $failures++; }
}

echo "=== Vault enrolment magic-link self-test ===\n\n";

// Simulate the wrap step (vaultIssueEnrolmentToken)
$master = random_bytes(16);
$token_raw = random_bytes(32);
$token_b64 = rtrim(strtr(base64_encode($token_raw), '+/', '-_'), '=');
$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
$kek = deriveKekArgon2id($token_b64, $salt);
$wrapped = cryptoEncryptV2($master, $kek);
$token_hash = password_hash($token_b64, PASSWORD_BCRYPT);

echo "1. Round-trip\n";
$kek2 = deriveKekArgon2id($token_b64, $salt);
$unwrapped = cryptoDecryptV2($wrapped, $kek2);
check('legitimate token recovers master key', $unwrapped === $master);
check('token_hash verifies the legitimate token', password_verify($token_b64, $token_hash));

echo "\n2. Wrong token rejected\n";
$bad_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$caught = false;
try {
    $kek_bad = deriveKekArgon2id($bad_token, $salt);
    cryptoDecryptV2($wrapped, $kek_bad);
} catch (Throwable $e) {
    $caught = true;
}
check('GCM tag rejects wrong token', $caught);
check('token_hash rejects wrong token', !password_verify($bad_token, $token_hash));

echo "\n3. Wrong salt rejected\n";
$caught = false;
try {
    $kek_bad = deriveKekArgon2id($token_b64, random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES));
    cryptoDecryptV2($wrapped, $kek_bad);
} catch (Throwable $e) {
    $caught = true;
}
check('GCM tag rejects wrong salt', $caught);

echo "\n4. Tamper detection\n";
$tampered = $wrapped;
$tampered[20] = chr(ord($tampered[20]) ^ 0x01);
$caught = false;
try {
    cryptoDecryptV2($tampered, deriveKekArgon2id($token_b64, $salt));
} catch (Throwable $e) {
    $caught = true;
}
check('tampered ciphertext rejected', $caught);

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
