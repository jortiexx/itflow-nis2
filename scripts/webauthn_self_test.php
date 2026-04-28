#!/usr/bin/env php
<?php
/*
 * WebAuthn library self-test (offline; no DB, no browser).
 *
 * Tests the building blocks of the WebAuthn library:
 *  - CBOR decoder against fixtures
 *  - COSE EC2 (P-256) key -> PEM round-trip via openssl
 *  - COSE RSA key -> PEM round-trip via openssl
 *  - End-to-end registration verification: build a synthetic
 *    attestationObject + clientDataJSON, run webauthnVerifyRegistration
 *  - End-to-end assertion verification: sign authData||sha256(cdj) with
 *    the same key, run webauthnVerifyAssertion
 *  - Counter regression rejection
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "This script must be run from the CLI.\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../includes/webauthn.php';

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

echo "=== WebAuthn library self-test ===\n\n";

// ---------------------------------------------------------------
echo "1. CBOR decoder primitives\n";
$tests_cbor = [
    ["\x00", 0],                          // unsigned 0
    ["\x17", 23],                         // unsigned 23
    ["\x18\x18", 24],                     // unsigned 24 (1-byte)
    ["\x19\x01\x00", 256],                // unsigned 256 (2-byte)
    ["\x20", -1],                         // negative -1
    ["\x29", -10],                        // negative -10
    ["\x42\x12\x34", "\x12\x34"],         // byte string len 2
    ["\x83\x01\x02\x03", [1, 2, 3]],      // array [1,2,3]
];
foreach ($tests_cbor as $i => [$bytes, $expected]) {
    $offset = 0;
    $got = webauthnCborDecode($bytes, $offset);
    check("CBOR fixture $i decodes correctly", $got === $expected);
}

echo "\n2. CBOR map decode\n";
// {-1: 1, -2: <32 zero bytes>}  — like a partial COSE EC key
$bytes = "\xa2"        // map of 2
       . "\x20"        // -1
       . "\x01"        // 1
       . "\x21"        // -2
       . "\x58\x20" . str_repeat("\x00", 32);  // byte string len 32
$offset = 0;
$got = webauthnCborDecode($bytes, $offset);
check('map decodes', is_array($got) && $got[-1] === 1 && $got[-2] === str_repeat("\x00", 32));

// ---------------------------------------------------------------
echo "\n3. COSE EC2 (P-256) -> PEM round-trip\n";
// Generate a real EC P-256 key, package as COSE, convert to PEM, verify a signature.
$ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
$details = openssl_pkey_get_details($ec);
$x = $details['ec']['x'];
$y = $details['ec']['y'];
// Pad to 32 bytes if openssl returned shorter (it sometimes drops leading zeros)
if (strlen($x) < 32) $x = str_repeat("\x00", 32 - strlen($x)) . $x;
if (strlen($y) < 32) $y = str_repeat("\x00", 32 - strlen($y)) . $y;

$cose_ec = [
    1  => COSE_KTY_EC2,    // kty
    3  => COSE_ALG_ES256,  // alg
    -1 => COSE_CRV_P256,   // crv
    -2 => $x,
    -3 => $y,
];
$pem = webauthnCoseKeyToPem($cose_ec);
$msg = 'webauthn-test';
openssl_sign($msg, $sig, $ec, OPENSSL_ALGO_SHA256);
$verified = openssl_verify($msg, $sig, $pem, OPENSSL_ALGO_SHA256);
check('COSE EC2 -> PEM verifies a signature from the matching key', $verified === 1);

// ---------------------------------------------------------------
echo "\n4. COSE RSA -> PEM round-trip\n";
$rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$rsa_details = openssl_pkey_get_details($rsa);
$cose_rsa = [
    1  => COSE_KTY_RSA,
    3  => COSE_ALG_RS256,
    -1 => $rsa_details['rsa']['n'],
    -2 => $rsa_details['rsa']['e'],
];
$rsa_pem = webauthnCoseKeyToPem($cose_rsa);
openssl_sign($msg, $rsa_sig, $rsa, OPENSSL_ALGO_SHA256);
check('COSE RSA -> PEM verifies a signature', openssl_verify($msg, $rsa_sig, $rsa_pem, OPENSSL_ALGO_SHA256) === 1);

// ---------------------------------------------------------------
echo "\n5. End-to-end registration verification (synthetic attestation)\n";
$rp_id    = 'itflow.example.com';
$origin   = 'https://itflow.example.com';
$challenge = random_bytes(32);

// Build clientDataJSON
$cdj = json_encode([
    'type'      => 'webauthn.create',
    'challenge' => webauthnB64UrlEncode($challenge),
    'origin'    => $origin,
], JSON_UNESCAPED_SLASHES);

// Build authenticatorData with attested credential data using our EC key
$cred_id = random_bytes(32);
$rp_id_hash = hash('sha256', $rp_id, true);
$flags = WEBAUTHN_FLAG_USER_PRESENT | WEBAUTHN_FLAG_USER_VERIFIED | WEBAUTHN_FLAG_AT;
$counter = pack('N', 0);
$aaguid = str_repeat("\x00", 16);

// Encode the COSE EC key as CBOR. We'll build it with a tiny encoder.
function cborMap(array $kvs): string
{
    $n = count($kvs);
    if ($n > 23) throw new Exception('test only supports small maps');
    $out = chr(0xa0 | $n);
    foreach ($kvs as $k => $v) {
        $out .= cborInt($k);
        $out .= is_string($v) ? cborBytes($v) : cborInt($v);
    }
    return $out;
}
function cborInt(int $i): string
{
    if ($i >= 0) {
        if ($i < 24)        return chr($i);
        if ($i < 256)       return "\x18" . chr($i);
        if ($i < 65536)     return "\x19" . pack('n', $i);
        return "\x1a" . pack('N', $i);
    }
    $u = -1 - $i;
    if ($u < 24)        return chr(0x20 | $u);
    if ($u < 256)       return "\x38" . chr($u);
    if ($u < 65536)     return "\x39" . pack('n', $u);
    return "\x3a" . pack('N', $u);
}
function cborBytes(string $b): string
{
    $len = strlen($b);
    if ($len < 24)        return chr(0x40 | $len) . $b;
    if ($len < 256)       return "\x58" . chr($len) . $b;
    if ($len < 65536)     return "\x59" . pack('n', $len) . $b;
    return "\x5a" . pack('N', $len) . $b;
}

$cose_ec_cbor = cborMap($cose_ec);
$cred_id_len = pack('n', strlen($cred_id));
$auth_data = $rp_id_hash . chr($flags) . $counter . $aaguid . $cred_id_len . $cred_id . $cose_ec_cbor;

// Wrap in attestationObject CBOR map: { fmt: "none", attStmt: {}, authData: <bytes> }
$attestation_object =
    "\xa3"                                              // map of 3
    . cborInt(0) /*placeholder*/  // we need text-string keys; build manually instead
;

// Rebuild attestationObject with text-string keys properly
function cborTextString(string $s): string
{
    $len = strlen($s);
    if ($len < 24) return chr(0x60 | $len) . $s;
    if ($len < 256) return "\x78" . chr($len) . $s;
    return "\x79" . pack('n', $len) . $s;
}
$attestation_object =
    "\xa3"
    . cborTextString('fmt') . cborTextString('none')
    . cborTextString('attStmt') . "\xa0"  // empty map
    . cborTextString('authData') . cborBytes($auth_data);

$reg_response = [
    'type' => 'public-key',
    'id'   => webauthnB64UrlEncode($cred_id),
    'response' => [
        'clientDataJSON'    => webauthnB64UrlEncode($cdj),
        'attestationObject' => webauthnB64UrlEncode($attestation_object),
    ],
];

try {
    $reg = webauthnVerifyRegistration($reg_response, $challenge, $origin, $rp_id);
    check('registration verifies', $reg['credential_id'] === $cred_id && $reg['alg'] === COSE_ALG_ES256);
} catch (Throwable $e) {
    echo "  [FAIL] registration verifies: " . $e->getMessage() . "\n";
    $tests++; $failures++;
}

// ---------------------------------------------------------------
echo "\n6. End-to-end assertion verification\n";
// Build a fresh assertion against the same EC key
$assertion_challenge = random_bytes(32);
$cdj_get = json_encode([
    'type'      => 'webauthn.get',
    'challenge' => webauthnB64UrlEncode($assertion_challenge),
    'origin'    => $origin,
], JSON_UNESCAPED_SLASHES);

// authenticatorData for assertion: rp_id_hash + flags + counter (no attested data)
$auth_data_get = $rp_id_hash
    . chr(WEBAUTHN_FLAG_USER_PRESENT | WEBAUTHN_FLAG_USER_VERIFIED)
    . pack('N', 1);  // counter = 1

$signed_input = $auth_data_get . hash('sha256', $cdj_get, true);
openssl_sign($signed_input, $assertion_sig, $ec, OPENSSL_ALGO_SHA256);

$assertion_response = [
    'type' => 'public-key',
    'id'   => webauthnB64UrlEncode($cred_id),
    'response' => [
        'clientDataJSON'    => webauthnB64UrlEncode($cdj_get),
        'authenticatorData' => webauthnB64UrlEncode($auth_data_get),
        'signature'         => webauthnB64UrlEncode($assertion_sig),
    ],
];

try {
    $new_count = webauthnVerifyAssertion(
        $assertion_response, $reg['public_key_pem'], 0, COSE_ALG_ES256,
        $assertion_challenge, $origin, $rp_id
    );
    check('assertion verifies and returns new counter=1', $new_count === 1);
} catch (Throwable $e) {
    echo "  [FAIL] assertion verifies: " . $e->getMessage() . "\n";
    $tests++; $failures++;
}

// ---------------------------------------------------------------
echo "\n7. Counter regression is rejected\n";
$caught = false;
try {
    // Replay the same assertion with stored counter already at 5
    webauthnVerifyAssertion(
        $assertion_response, $reg['public_key_pem'], 5, COSE_ALG_ES256,
        $assertion_challenge, $origin, $rp_id
    );
} catch (WebAuthnException $e) {
    $caught = true;
}
check('replay with higher stored counter is rejected', $caught);

// ---------------------------------------------------------------
echo "\n8. Wrong challenge is rejected\n";
$caught = false;
try {
    webauthnVerifyAssertion(
        $assertion_response, $reg['public_key_pem'], 0, COSE_ALG_ES256,
        random_bytes(32), $origin, $rp_id
    );
} catch (WebAuthnException $e) {
    $caught = true;
}
check('mismatching challenge is rejected', $caught);

// ---------------------------------------------------------------
echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
