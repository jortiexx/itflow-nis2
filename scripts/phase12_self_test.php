#!/usr/bin/env php
<?php
/*
 * Phase 12 self-test (offline; no DB).
 *
 * Verifies decryptOptionalField behaviour:
 *  - empty / null in → empty out
 *  - plaintext (no v2/v3 prefix) passes through unchanged
 *  - v2 / v3 prefix triggers decrypt path (without DB the decrypt fails
 *    because there is no session/client master, but the dispatch is
 *    correct — we test the prefix detection)
 *  - non-prefixed binary garbage stays as-is (does NOT route to v1
 *    decrypt, which would be wrong for these never-encrypted fields)
 */

if (php_sapi_name() !== 'cli') { fwrite(STDERR, "CLI only\n"); exit(1); }

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

echo "=== Phase 12 self-test ===\n\n";

echo "1. Empty / null inputs\n";
check('null returns empty string', decryptOptionalField(null, 1) === '');
check('empty string returns empty', decryptOptionalField('', 1) === '');

echo "\n2. Plaintext passthrough\n";
check('TOTP-style seed unchanged', decryptOptionalField('JBSWY3DPEHPK3PXP', 1) === 'JBSWY3DPEHPK3PXP');
check('multi-line note unchanged',
    decryptOptionalField("Server: srv01\nRoot pwd: hunter2", 1) === "Server: srv01\nRoot pwd: hunter2");
check('short alphanumeric unchanged', decryptOptionalField('abc123', 1) === 'abc123');

echo "\n3. Prefix detection (offline check)\n";
// Without DB / session we can't fully exercise decryptOptionalField on
// prefixed values (the v3 path needs $mysqli + session). Verify the
// prefix detectors instead, which are what decryptOptionalField uses
// to decide whether to attempt a decrypt or pass plaintext through.
check('v2: prefix detected', isCredentialV2('v2:foo') === true);
check('v3: prefix detected', isCredentialV3('v3:foo') === true);
check('plaintext not v2',     isCredentialV2('JBSWY3DPEHPK3PXP') === false);
check('plaintext not v3',     isCredentialV3('JBSWY3DPEHPK3PXP') === false);
check('v2 not v3',            isCredentialV3('v2:foo') === false);
check('v3 not v2',            isCredentialV2('v3:foo') === false);

echo "\n4. Encrypt + decrypt round-trip via v3\n";
$client_master = random_bytes(16);
$secret = 'JBSWY3DPEHPK3PXP'; // example TOTP seed
$encrypted = encryptCredentialEntryV3($secret, $client_master);
check('encrypted output starts with v3:', isCredentialV3($encrypted));
check('encrypted differs from plaintext', $encrypted !== $secret);
check('round-trip via low-level helper', decryptCredentialEntryV3($encrypted, $client_master) === $secret);

echo "\n5. Note round-trip\n";
$note = "Multi-line note\nLine 2\nWith special chars: <>&\"'";
$encrypted_note = encryptCredentialEntryV3($note, $client_master);
check('note round-trip preserves whitespace and special chars',
    decryptCredentialEntryV3($encrypted_note, $client_master) === $note);

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
