#!/usr/bin/env php
<?php
/*
 * Vault PRF self-test (offline).
 *
 * Verifies the PRF-output → KEK derivation and the wrap/unwrap cycle
 * that wraps the master key under a PRF KEK. The actual WebAuthn
 * ceremony is browser-side; here we exercise only the server-side
 * crypto path so a regression in HKDF / AES-256-GCM round-trip would
 * be caught before any browser test.
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

echo "=== Vault PRF self-test ===\n\n";

echo "1. KEK derivation\n";
$prf = random_bytes(32);
$kek1 = vaultDeriveKekFromPrf($prf);
$kek2 = vaultDeriveKekFromPrf($prf);
check('deterministic (same input = same KEK)', hash_equals($kek1, $kek2));
check('output is 32 bytes', strlen($kek1) === 32);

$kek3 = vaultDeriveKekFromPrf(random_bytes(32));
check('different PRF output = different KEK', !hash_equals($kek1, $kek3));

$caught = false;
try { vaultDeriveKekFromPrf(random_bytes(31)); } catch (RuntimeException $e) { $caught = true; }
check('rejects PRF output that is not 32 bytes', $caught);

echo "\n2. Master key wrap/unwrap under PRF KEK\n";
$master = random_bytes(16);
$prf_a  = random_bytes(32);
$kek    = vaultDeriveKekFromPrf($prf_a);
$wrapped = cryptoEncryptV2($master, $kek);
$unwrapped = cryptoDecryptV2($wrapped, vaultDeriveKekFromPrf($prf_a));
check('round-trip preserves master key', $unwrapped === $master);

$caught = false;
try { cryptoDecryptV2($wrapped, vaultDeriveKekFromPrf(random_bytes(32))); }
catch (Throwable $e) { $caught = true; }
check('wrong PRF output rejects (GCM auth tag)', $caught);

echo "\n3. Same PRF + tampered wrapping fails\n";
$tampered = $wrapped;
$tampered[20] = chr(ord($tampered[20]) ^ 0x01);
$caught = false;
try { cryptoDecryptV2($tampered, vaultDeriveKekFromPrf($prf_a)); }
catch (Throwable $e) { $caught = true; }
check('tampered ciphertext rejected', $caught);

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
