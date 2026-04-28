#!/usr/bin/env php
<?php
/*
 * NIS2 fork crypto self-test
 *
 * Round-trips the v2 crypto stack to verify:
 *   - AES-256-GCM encrypt/decrypt
 *   - Argon2id KEK derivation
 *   - HKDF master-key expansion
 *   - User-specific key wrap/unwrap
 *   - Credential entry wrap/unwrap
 *   - Tamper detection (GCM auth tag rejects modified ciphertexts)
 *
 * Run from CLI:
 *   php scripts/crypto_self_test.php
 *
 * Exits 0 on success, 1 on any failure.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "This script must be run from the CLI.\n");
    exit(1);
}

chdir(__DIR__ . '/..');

// Minimal bootstrap. functions.php pulls in helpers; we don't need the DB.
require_once __DIR__ . '/../functions.php';

$failures = 0;
$tests    = 0;

function check(string $label, bool $ok): void
{
    global $failures, $tests;
    $tests++;
    if ($ok) {
        echo "  [PASS] $label\n";
    } else {
        echo "  [FAIL] $label\n";
        $failures++;
    }
}

echo "=== NIS2 fork crypto self-test ===\n\n";

// -----------------------------------------------------------------
echo "1. AES-256-GCM round-trip\n";
$key32 = random_bytes(32);
$pt    = "the quick brown fox jumps over the lazy dog";
$blob  = cryptoEncryptV2($pt, $key32);
check('blob has version+algo header', $blob[0] === "\x02" && $blob[1] === "\x01");
check('blob length = 2 + 12 + ' . strlen($pt) . ' + 16', strlen($blob) === 2 + 12 + strlen($pt) + 16);
check('decrypt returns original plaintext', cryptoDecryptV2($blob, $key32) === $pt);

// -----------------------------------------------------------------
echo "\n2. AES-256-GCM tamper detection\n";
$tampered = $blob;
$tampered[20] = chr(ord($tampered[20]) ^ 0x01);  // flip a bit in the ciphertext
$caught = false;
try {
    cryptoDecryptV2($tampered, $key32);
} catch (Throwable $e) {
    $caught = true;
}
check('tampered ciphertext rejected', $caught);

$wrong_key = random_bytes(32);
$caught = false;
try {
    cryptoDecryptV2($blob, $wrong_key);
} catch (Throwable $e) {
    $caught = true;
}
check('wrong key rejected', $caught);

// -----------------------------------------------------------------
echo "\n3. Argon2id KEK derivation\n";
$pw   = 'correct horse battery staple';
$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
$kek1 = deriveKekArgon2id($pw, $salt);
$kek2 = deriveKekArgon2id($pw, $salt);
check('deterministic (same input = same output)', hash_equals($kek1, $kek2));
check('output is 32 bytes', strlen($kek1) === 32);

$kek3 = deriveKekArgon2id($pw, random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES));
check('different salt = different output', !hash_equals($kek1, $kek3));

$kek4 = deriveKekArgon2id($pw . 'x', $salt);
check('different password = different output', !hash_equals($kek1, $kek4));

// -----------------------------------------------------------------
echo "\n4. User-specific key wrap/unwrap\n";
$master_key   = random_bytes(16);  // legacy 16-byte master
$wrapped      = encryptUserSpecificKeyV2($master_key, $pw);
$unwrapped    = decryptUserSpecificKeyV2($wrapped, $pw);
check('round-trip preserves master key', $master_key === $unwrapped);

$caught = false;
try {
    decryptUserSpecificKeyV2($wrapped, $pw . '_wrong');
} catch (Throwable $e) {
    $caught = true;
}
check('wrong password rejected', $caught);

// -----------------------------------------------------------------
echo "\n5. HKDF master-key expansion\n";
$expanded1 = expandMasterKeyToAes256($master_key);
$expanded2 = expandMasterKeyToAes256($master_key);
check('deterministic', hash_equals($expanded1, $expanded2));
check('output is 32 bytes', strlen($expanded1) === 32);

$expanded3 = expandMasterKeyToAes256(random_bytes(16));
check('different master = different expansion', !hash_equals($expanded1, $expanded3));

// -----------------------------------------------------------------
echo "\n6. Credential entry round-trip\n";
$secret    = "p@ssw0rd!with-special-chars-\xc3\xa9\xc3\xab\xe2\x82\xac";
$encrypted = encryptCredentialEntryV2($secret, $master_key);
check('output starts with v2: prefix', isCredentialV2($encrypted));
$decrypted = decryptCredentialEntryV2($encrypted, $master_key);
check('round-trip preserves plaintext', $decrypted === $secret);

$wrong_master = random_bytes(16);
$caught = false;
try {
    decryptCredentialEntryV2($encrypted, $wrong_master);
} catch (Throwable $e) {
    $caught = true;
}
check('wrong master key rejected', $caught);

// -----------------------------------------------------------------
echo "\n7. Legacy detection\n";
$legacy = "abc123XYZ_-______" . base64_encode("ciphertext");  // 16-char IV + base64
check('legacy v1 not detected as v2', isCredentialV2($legacy) === false);
check('v2 detected as v2', isCredentialV2('v2:abc123') === true);

// -----------------------------------------------------------------
echo "\n8. IV uniqueness\n";
$blob_a = cryptoEncryptV2($pt, $key32);
$blob_b = cryptoEncryptV2($pt, $key32);
check('two encryptions of same plaintext produce different ciphertexts', $blob_a !== $blob_b);

// -----------------------------------------------------------------
echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
