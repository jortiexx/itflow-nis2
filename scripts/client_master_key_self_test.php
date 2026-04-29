#!/usr/bin/env php
<?php
/*
 * Per-client master key self-test (offline; no DB).
 *
 * Exercises the v3 credential format: each client's data is encrypted
 * under a per-client master key, which is itself wrapped under the shared
 * session master key.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../functions.php';

$failures = 0;
$tests    = 0;
function check(string $label, bool $ok): void
{
    global $failures, $tests;
    $tests++;
    if ($ok) echo "  [PASS] $label\n";
    else { echo "  [FAIL] $label\n"; $failures++; }
}

echo "=== Per-client master key self-test ===\n\n";

// Simulate the wrapping chain:
//   shared_master  ->  client_master_key  ->  credential_v3
$shared_master = random_bytes(16);

// Client A and Client B each get their own random master key.
$client_a_master = random_bytes(16);
$client_b_master = random_bytes(16);

// Wrap each under the shared master (HKDF-expanded).
$shared_kek = expandMasterKeyToAes256($shared_master);
$wrapped_a  = cryptoEncryptV2($client_a_master, $shared_kek);
$wrapped_b  = cryptoEncryptV2($client_b_master, $shared_kek);

echo "1. Client master key wrap/unwrap\n";
$un_a = cryptoDecryptV2($wrapped_a, expandMasterKeyToAes256($shared_master));
$un_b = cryptoDecryptV2($wrapped_b, expandMasterKeyToAes256($shared_master));
check('client A round-trip', $un_a === $client_a_master);
check('client B round-trip', $un_b === $client_b_master);
check('A and B have different keys', $un_a !== $un_b);

echo "\n2. v3 credential format\n";
$secret_a = "client A admin password";
$secret_b = "client B admin password";

$enc_a = encryptCredentialEntryV3($secret_a, $client_a_master);
$enc_b = encryptCredentialEntryV3($secret_b, $client_b_master);

check('v3 ciphertext starts with v3:', isCredentialV3($enc_a) && isCredentialV3($enc_b));
check('client A round-trip', decryptCredentialEntryV3($enc_a, $client_a_master) === $secret_a);
check('client B round-trip', decryptCredentialEntryV3($enc_b, $client_b_master) === $secret_b);

echo "\n3. Cross-client decrypt fails\n";
$caught = false;
try { decryptCredentialEntryV3($enc_a, $client_b_master); }
catch (Throwable $e) { $caught = true; }
check('client B key cannot decrypt client A credentials', $caught);

$caught = false;
try { decryptCredentialEntryV3($enc_b, $client_a_master); }
catch (Throwable $e) { $caught = true; }
check('client A key cannot decrypt client B credentials', $caught);

echo "\n4. v3 prefix is unambiguous\n";
$v2_legacy = "abc123XYZ_-______" . base64_encode("v2_or_v1_data");
check('legacy ciphertext is not detected as v3', isCredentialV3($v2_legacy) === false);
check('v3 detected', isCredentialV3('v3:abc') === true);
check('v2 vs v3 distinguished', isCredentialV2('v3:abc') === false);

echo "\n5. Tamper detection across the wrapping chain\n";
$tampered_outer = $enc_a;
$tampered_outer[5] = chr(ord($tampered_outer[5]) ^ 0x01);
$caught = false;
try { decryptCredentialEntryV3($tampered_outer, $client_a_master); }
catch (Throwable $e) { $caught = true; }
check('tampered v3 ciphertext rejected', $caught);

$tampered_wrap = $wrapped_a;
$tampered_wrap[20] = chr(ord($tampered_wrap[20]) ^ 0x01);
$caught = false;
try { cryptoDecryptV2($tampered_wrap, expandMasterKeyToAes256($shared_master)); }
catch (Throwable $e) { $caught = true; }
check('tampered client-master wrapping rejected', $caught);

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
