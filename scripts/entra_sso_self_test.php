#!/usr/bin/env php
<?php
/*
 * Entra SSO helper self-test.
 *
 * Verifies the cryptographic plumbing in includes/entra_sso.php without
 * making any network calls: PKCE generation, base64url round-trip, RSA
 * JWK -> PEM -> openssl_verify against a self-issued JWT.
 *
 * Run from CLI:
 *   php scripts/entra_sso_self_test.php
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "This script must be run from the CLI.\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../includes/entra_sso.php';

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

echo "=== Entra SSO helpers self-test ===\n\n";

// ---------------------------------------------------
echo "1. PKCE generation\n";
$p = entraGeneratePkcePair();
check('verifier present',  !empty($p['verifier']));
check('challenge present', !empty($p['challenge']));
$expected_challenge = entraBase64UrlEncode(hash('sha256', $p['verifier'], true));
check('challenge = base64url(sha256(verifier))', $expected_challenge === $p['challenge']);
$p2 = entraGeneratePkcePair();
check('two pairs produce different verifiers', $p['verifier'] !== $p2['verifier']);

// ---------------------------------------------------
echo "\n2. base64url round-trip\n";
$random  = random_bytes(64);
$encoded = entraBase64UrlEncode($random);
$decoded = entraBase64UrlDecode($encoded);
check('round-trip equals input', $decoded === $random);
check('no padding in encoded', strpos($encoded, '=') === false);
check('no + or / in encoded',  strpbrk($encoded, '+/') === false);

// ---------------------------------------------------
echo "\n3. JWK (RSA) -> PEM via openssl\n";
// Generate a fresh RSA key pair, derive JWK n/e from it, convert back, verify.
$pkey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$details = openssl_pkey_get_details($pkey);
$jwk = [
    'kty' => 'RSA',
    'kid' => 'test-key',
    'n'   => entraBase64UrlEncode($details['rsa']['n']),
    'e'   => entraBase64UrlEncode($details['rsa']['e']),
];
$pem_from_jwk = entraJwkRsaToPem($jwk);
$pem_from_openssl = $details['key'];

// Both PEMs should accept the same signature (we round-trip a sign+verify).
$msg = 'test message';
openssl_sign($msg, $sig, $pkey, OPENSSL_ALGO_SHA256);
$verified = openssl_verify($msg, $sig, $pem_from_jwk, OPENSSL_ALGO_SHA256);
check('JWK-derived PEM verifies a signature made with the matching private key', $verified === 1);

$verified_native = openssl_verify($msg, $sig, $pem_from_openssl, OPENSSL_ALGO_SHA256);
check('Native-extracted PEM verifies the same signature', $verified_native === 1);

// Wrong-key scenario
$pkey_other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_sign($msg, $sig_other, $pkey_other, OPENSSL_ALGO_SHA256);
$rejected = openssl_verify($msg, $sig_other, $pem_from_jwk, OPENSSL_ALGO_SHA256);
check('JWK-derived PEM rejects a signature made with a different key', $rejected === 0);

// ---------------------------------------------------
echo "\n4. End-to-end: build a JWT, sign it, validate via entraValidateIdToken-like path\n";
// We can't call entraValidateIdToken directly without network access (it fetches JWKS),
// but we can exercise the signature-verification piece using the same primitives.
$header  = json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $jwk['kid']]);
$payload = json_encode([
    'iss'   => 'https://login.microsoftonline.com/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/v2.0',
    'aud'   => 'cccccccc-bbbb-aaaa-9999-888888888888',
    'tid'   => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    'oid'   => '11111111-2222-3333-4444-555555555555',
    'email' => 'user@example.com',
    'name'  => 'Test User',
    'iat'   => time(),
    'nbf'   => time(),
    'exp'   => time() + 3600,
    'nonce' => 'expected-nonce-12345',
]);
$h64 = entraBase64UrlEncode($header);
$p64 = entraBase64UrlEncode($payload);
$signing_input = $h64 . '.' . $p64;
openssl_sign($signing_input, $sig, $pkey, OPENSSL_ALGO_SHA256);
$jwt = $signing_input . '.' . entraBase64UrlEncode($sig);

// Manually replicate the inner signature verification logic
$pem = entraJwkRsaToPem($jwk);
$verified = openssl_verify($signing_input, $sig, $pem, OPENSSL_ALGO_SHA256);
check('round-tripped JWT signature verifies via JWK->PEM path', $verified === 1);

// ---------------------------------------------------
echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
