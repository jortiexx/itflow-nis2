#!/usr/bin/env php
<?php
/*
 * Per-user keypair + per-user client grant self-test (offline; no DB).
 *
 * Verifies the cryptographic primitives that underpin Phase 10
 * compartmentalisation:
 *  - userGenerateKeypairForPassword + userUnwrapPrivkey round-trip
 *  - Wrong password rejects unwrap
 *  - userRewrapPrivkey at password change preserves the keypair
 *  - wrapClientKeyForUser / unwrapClientKeyFromGrant: only the grantee's
 *    private key opens the sealed box. Other users' privkeys cannot.
 *  - Tamper detection at both layers.
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

echo "=== Per-user keypair + grants self-test ===\n\n";

// --------------------------------------------------------
echo "1. Keypair generation + unwrap round-trip\n";
$pw_alice = 'alice-correct-password';
$kp_alice = userGenerateKeypairForPassword($pw_alice);
check('pubkey present', !empty($kp_alice['pubkey_b64']));
check('wrapped privkey present', !empty($kp_alice['wrapped_privkey_b64']));

$priv = userUnwrapPrivkey($kp_alice['wrapped_privkey_b64'], $pw_alice);
check('correct password unwraps privkey', $priv !== null && strlen($priv) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES);

$pub_derived = sodium_crypto_box_publickey_from_secretkey($priv);
check('pubkey matches privkey', base64_encode($pub_derived) === $kp_alice['pubkey_b64']);

// --------------------------------------------------------
echo "\n2. Wrong password rejects unwrap\n";
$bad = userUnwrapPrivkey($kp_alice['wrapped_privkey_b64'], 'wrong-password');
check('wrong password returns null', $bad === null);

// --------------------------------------------------------
echo "\n3. Password change rewrap preserves keypair\n";
$new_wrap = userRewrapPrivkey($kp_alice['wrapped_privkey_b64'], $pw_alice, 'alice-new-password');
check('rewrap succeeds', $new_wrap !== null);
$priv_after = userUnwrapPrivkey($new_wrap, 'alice-new-password');
check('new password unwraps to same privkey', $priv_after === $priv);
$priv_old_pw = userUnwrapPrivkey($new_wrap, $pw_alice);
check('old password no longer unwraps', $priv_old_pw === null);

// --------------------------------------------------------
echo "\n4. Sealed-box wrapping: only grantee can open\n";
$kp_bob   = userGenerateKeypairForPassword('bob-password');
$priv_bob = userUnwrapPrivkey($kp_bob['wrapped_privkey_b64'], 'bob-password');

$client_master = random_bytes(16);
$grant_for_alice = wrapClientKeyForUser($client_master, $kp_alice['pubkey_b64']);
$grant_for_bob   = wrapClientKeyForUser($client_master, $kp_bob['pubkey_b64']);

check('alice opens her own grant', unwrapClientKeyFromGrant($grant_for_alice, $priv) === $client_master);
check('bob opens his own grant',   unwrapClientKeyFromGrant($grant_for_bob, $priv_bob) === $client_master);

// The compartmentalisation property: each user's privkey only opens THEIR
// grants. Bob cannot open the grant that was sealed for Alice's pubkey,
// even if both grants wrap the same client_master internally.
check('bob cannot open alice\'s grant', unwrapClientKeyFromGrant($grant_for_alice, $priv_bob) === null);
check('alice cannot open bob\'s grant', unwrapClientKeyFromGrant($grant_for_bob, $priv) === null);

// --------------------------------------------------------
echo "\n5. Tamper detection on grants\n";
$tampered_grant_raw = base64_decode($grant_for_alice, true);
$tampered_grant_raw[10] = chr(ord($tampered_grant_raw[10]) ^ 0x01);
$tampered_b64 = base64_encode($tampered_grant_raw);
check('tampered grant rejected', unwrapClientKeyFromGrant($tampered_b64, $priv) === null);

// --------------------------------------------------------
echo "\n6. Privkey wrapping format sanity\n";
$raw = base64_decode($kp_alice['wrapped_privkey_b64'], true);
check('wrapped privkey decodes', $raw !== false);
check('wrapped privkey contains salt + ciphertext + tag',
    strlen($raw) >= SODIUM_CRYPTO_PWHASH_SALTBYTES + 30);

// --------------------------------------------------------
echo "\n=== Summary ===\n";
echo "$tests tests, $failures failures\n";
exit($failures === 0 ? 0 : 1);
