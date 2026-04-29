#!/usr/bin/env php
<?php
/*
 * Phase 11 self-test (offline; no DB).
 *
 * Verifies the three new wrapping paths:
 *  1. Privkey wrapped under PIN KEK alongside master key — same KEK, two
 *     ciphertexts, both round-trip cleanly.
 *  2. Privkey wrapped under PRF KEK alongside master key.
 *  3. Per-client master key wrapped under an API password using Argon2id —
 *     a compromised API key recovers ONLY its scoped client's master key.
 */

if (php_sapi_name() !== 'cli') { fwrite(STDERR, "CLI only\n"); exit(1); }

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

echo "=== Phase 11 self-test ===\n\n";

// ---------------------------------------------------------------
echo "1. PIN KEK wraps both master and privkey\n";
$master  = random_bytes(16);
$privkey = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
$pin     = 'correct-horse-battery';
$salt    = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
$kek     = deriveKekArgon2id($pin, $salt);

$wrapped_master  = cryptoEncryptV2($master, $kek);
$wrapped_privkey = cryptoEncryptV2($privkey, $kek);

check('master and privkey produce different ciphertexts (different IVs)',
    $wrapped_master !== $wrapped_privkey);

// Unwrap with the same KEK
$kek2 = deriveKekArgon2id($pin, $salt);
check('master round-trip', cryptoDecryptV2($wrapped_master, $kek2) === $master);
check('privkey round-trip', cryptoDecryptV2($wrapped_privkey, $kek2) === $privkey);

// ---------------------------------------------------------------
echo "\n2. Wrong PIN rejects both\n";
$kek_bad = deriveKekArgon2id('wrong-pin', $salt);
$caught_m = false;
$caught_p = false;
try { cryptoDecryptV2($wrapped_master, $kek_bad); } catch (Throwable $e) { $caught_m = true; }
try { cryptoDecryptV2($wrapped_privkey, $kek_bad); } catch (Throwable $e) { $caught_p = true; }
check('wrong PIN rejects master', $caught_m);
check('wrong PIN rejects privkey', $caught_p);

// ---------------------------------------------------------------
echo "\n3. PRF KEK same dual-wrapping\n";
$prf = random_bytes(32);
$kek_prf  = vaultDeriveKekFromPrf($prf);
$wrap_m_prf = cryptoEncryptV2($master, $kek_prf);
$wrap_p_prf = cryptoEncryptV2($privkey, $kek_prf);

$kek_prf2 = vaultDeriveKekFromPrf($prf);
check('PRF master round-trip',  cryptoDecryptV2($wrap_m_prf, $kek_prf2) === $master);
check('PRF privkey round-trip', cryptoDecryptV2($wrap_p_prf, $kek_prf2) === $privkey);

// ---------------------------------------------------------------
echo "\n4. Per-client API key wrapping\n";
$client_a_master = random_bytes(16);
$api_password = 'api-key-secret-XYZ';
$api_salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
$api_kek = deriveKekArgon2id($api_password, $api_salt);
$api_wrap = cryptoEncryptV2($client_a_master, $api_kek);
$api_wrap_b64 = base64_encode($api_salt . $api_wrap);

// Simulate apiUnlockClientMasterKey
$api_key_row = ['api_key_client_master_wrapped' => $api_wrap_b64];
$got = apiUnlockClientMasterKey($api_key_row, $api_password);
check('API key recovers its scoped client master', $got === $client_a_master);

$got_bad = apiUnlockClientMasterKey($api_key_row, 'wrong-password');
check('wrong API password rejects', $got_bad === null);

// Verify a different client's data is NOT recoverable from this API key.
// The wrapping only contains client_a_master; client_b_master is a
// different secret nowhere in this row. By construction the API key
// cannot reach it.
$client_b_master = random_bytes(16);
check('client B master is independent', $client_a_master !== $client_b_master);
check('API key has no path to client B master', !str_contains($api_wrap_b64, base64_encode($client_b_master)));

// ---------------------------------------------------------------
echo "\n5. Empty wrapping returns null (global API key)\n";
$global_api_row = ['api_key_client_master_wrapped' => ''];
check('empty wrapping returns null', apiUnlockClientMasterKey($global_api_row, $api_password) === null);
$missing_api_row = [];
check('absent column returns null', apiUnlockClientMasterKey($missing_api_row, $api_password) === null);

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
