#!/usr/bin/env php
<?php
/*
 * Phase 13 self-test (offline; no DB).
 *
 * Verifies the file-storage primitives introduced in phase 13:
 *   - encryptFileAtRest / decryptFileAtRest round-trip
 *   - SHA-256 stability and length
 *   - fileVerifyMimeMatchesExtension allowlist behaviour
 *
 * The encrypt/decrypt helpers normally pull the per-client master key from
 * the database via getClientMasterKeyViaGrant / ensureClientMasterKey. For
 * the offline test we simulate the wrapping chain directly, exercising the
 * same expandMasterKeyToAes256 + AES-GCM path that the production helper
 * uses.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/file_storage.php';

$failures = 0;
$tests    = 0;
function check(string $label, bool $ok): void
{
    global $failures, $tests;
    $tests++;
    if ($ok) echo "  [PASS] $label\n";
    else { echo "  [FAIL] $label\n"; $failures++; }
}

echo "=== Phase 13 self-test ===\n\n";

echo "1. SHA-256 hashing\n";
$payload = "the quick brown fox jumps over the lazy dog";
$digest  = fileHashSha256($payload);
check('hash is 32 raw bytes', strlen($digest) === 32);
check('hash matches reference vector',
    bin2hex($digest) === '05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec');
check('different input → different hash',
    fileHashSha256("the quick brown fox jumps over the lazy cat") !== $digest);
check('hash is stable across calls',
    fileHashSha256($payload) === $digest);

echo "\n2. AES-256-GCM round-trip via openssl_encrypt (mirrors helper)\n";
$client_master = random_bytes(16);
$key32         = expandMasterKeyToAes256($client_master);
$iv            = random_bytes(12);
$plaintext     = str_repeat("the rain in spain ", 1000); // ~18 KB
$tag           = '';
$ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
check('encryption succeeded', $ct !== false);
check('ciphertext differs from plaintext', $ct !== $plaintext);
check('tag is 16 bytes', strlen($tag) === 16);
check('iv is 12 bytes', strlen($iv) === 12);

$pt = openssl_decrypt($ct, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag);
check('decryption recovers plaintext', $pt === $plaintext);

echo "\n3. Tamper detection\n";
$ct_bad = $ct;
$ct_bad[10] = chr(ord($ct_bad[10]) ^ 0x01);
$pt_bad = openssl_decrypt($ct_bad, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag);
check('flipped bit in ciphertext is rejected', $pt_bad === false);

$tag_bad = $tag;
$tag_bad[0] = chr(ord($tag_bad[0]) ^ 0x01);
$pt_bad2 = openssl_decrypt($ct, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag_bad);
check('flipped bit in tag is rejected', $pt_bad2 === false);

$key_other = expandMasterKeyToAes256(random_bytes(16));
$pt_bad3 = openssl_decrypt($ct, 'aes-256-gcm', $key_other, OPENSSL_RAW_DATA, $iv, $tag);
check('wrong key cannot decrypt', $pt_bad3 === false);

echo "\n4. MIME / extension validation\n";
$tmp = tempnam(sys_get_temp_dir(), 'p13_');
file_put_contents($tmp, "Hello world\n");
$res = fileVerifyMimeMatchesExtension($tmp, 'txt');
check('plain text claiming .txt is accepted', $res['ok'] === true);

// Minimal valid 1x1 PNG (well-known 67-byte fixture). libmagic recognises
// this as image/png because it has signature + IHDR + IDAT + IEND chunks.
$png_tmp = tempnam(sys_get_temp_dir(), 'p13_png_');
$minimal_png_hex =
    '89504E470D0A1A0A' .                              // signature
    '0000000D49484452000000010000000108060000001F15C489' . // IHDR
    '0000000D4944415478DA62000000000500010D0A2DB4' .  // IDAT
    '0000000049454E44AE426082';                       // IEND
file_put_contents($png_tmp, hex2bin($minimal_png_hex));
$res_png = fileVerifyMimeMatchesExtension($png_tmp, 'png');
check('valid PNG claiming .png is accepted (detected: ' . ($res_png['detected'] ?? 'null') . ')',
    $res_png['ok'] === true);

// Same PNG bytes claiming to be a .pdf — must be rejected.
$res_lying = fileVerifyMimeMatchesExtension($png_tmp, 'pdf');
check('PNG bytes claiming .pdf are rejected', $res_lying['ok'] === false);

// Plain text claiming to be .exe (not in allowlist) — rejected on extension.
$res_exe = fileVerifyMimeMatchesExtension($tmp, 'exe');
check('extension not in allowlist is rejected', $res_exe['ok'] === false);

@unlink($tmp);
@unlink($png_tmp);

echo "\n5. End-to-end blob round-trip simulating encryptFileAtRest\n";
// Mirror the helper logic exactly: random IV, AES-256-GCM, tag-on-the-side.
$big = random_bytes(64 * 1024); // 64 KB binary blob
$iv2 = random_bytes(12);
$tag2 = '';
$ct2 = openssl_encrypt($big, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv2, $tag2, '', 16);
check('64KB blob encrypts', $ct2 !== false);
check('64KB blob ciphertext same length as plaintext (GCM)', strlen($ct2) === strlen($big));
$pt2 = openssl_decrypt($ct2, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv2, $tag2);
check('64KB blob round-trips', $pt2 === $big);

// SHA-256 verification path used at download time.
$sha = fileHashSha256($big);
$sha_ct = hash('sha256', $ct2, true);
check('plaintext SHA matches re-hashed plaintext after decrypt',
    hash_equals($sha, fileHashSha256($pt2)));
check('plaintext SHA does NOT match ciphertext SHA',
    !hash_equals($sha, $sha_ct));

echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
