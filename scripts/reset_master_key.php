#!/usr/bin/env php
<?php
/*
 * One-time recovery script: regenerate the master key for a user whose
 * v1 wrapping is irrecoverably corrupt.
 *
 * Use only when:
 *   - The user cannot decrypt the existing wrapping (login works but vault
 *     stays locked because unlockUserMasterKey returns null).
 *   - There are NO stored credentials encrypted under the current master
 *     key (regenerating destroys access to anything previously encrypted).
 *
 * Usage:
 *   php scripts/reset_master_key.php <user_id> <plaintext_password>
 *
 * The password is verified against the existing bcrypt hash in users.
 * On success a fresh 16-byte master key is generated and wrapped with
 * PBKDF2-SHA256(password) into a clean v1 column. v2 is cleared so the
 * next login lazily re-wraps it as v2.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}
if ($argc < 3) {
    fwrite(STDERR, "Usage: php reset_master_key.php <user_id> <password>\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once 'config.php';
require_once 'functions.php';

$user_id  = intval($argv[1]);
$password = $argv[2];

$row = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT user_id, user_email, user_password,
            LENGTH(user_specific_encryption_ciphertext) AS v1_len
     FROM users WHERE user_id = $user_id"));
if (!$row) {
    fwrite(STDERR, "User $user_id not found.\n");
    exit(1);
}

if (!password_verify($password, $row['user_password'])) {
    fwrite(STDERR, "Password does not match the bcrypt hash for {$row['user_email']}. Aborting.\n");
    exit(2);
}

echo "Resetting master key for user_id=$user_id ({$row['user_email']})\n";
echo "Existing v1 wrapping length was: " . ($row['v1_len'] ?: '(null)') . " — will be replaced.\n";

// Generate a fresh 16-byte master key and wrap it cleanly.
$master_key = random_bytes(16);
$iv         = random_bytes(16);
$salt       = random_bytes(16);
$kdhash     = hash_pbkdf2('sha256', $password, $salt, 100000, 16);
$ciphertext = openssl_encrypt($master_key, 'aes-128-cbc', $kdhash, 0, $iv);

if ($ciphertext === false) {
    fwrite(STDERR, "openssl_encrypt failed: " . openssl_error_string() . "\n");
    exit(3);
}

$new_v1 = $salt . $iv . $ciphertext;

// Sanity: verify we can decrypt it back with the same password.
$verify_pt = openssl_decrypt(
    substr($new_v1, 32),
    'aes-128-cbc',
    hash_pbkdf2('sha256', $password, substr($new_v1, 0, 16), 100000, 16),
    0,
    substr($new_v1, 16, 16)
);
if ($verify_pt !== $master_key) {
    fwrite(STDERR, "Self-verify failed; aborting without DB write.\n");
    exit(4);
}

$new_v1_e = mysqli_real_escape_string($mysqli, $new_v1);
mysqli_query($mysqli,
    "UPDATE users
     SET user_specific_encryption_ciphertext = '$new_v1_e',
         user_specific_encryption_ciphertext_v2 = NULL
     WHERE user_id = $user_id");

echo "OK. New v1 wrapping length: " . strlen($new_v1) . " bytes.\n";
echo "v2 cleared (will regenerate on next login).\n";
echo "\nNext steps:\n";
echo "  1. Log out of ITFlow.\n";
echo "  2. Log in again with the same password.\n";
echo "  3. New Credential button should now be enabled.\n";
