<?php
/*
 * Vault unlock helpers.
 *
 * Vault unlock methods give an agent a way to obtain the master key
 * without their account password. The current shipped method is "pin"
 * (Argon2id-derived KEK + AES-256-GCM wrap). Schema is forward-compatible
 * with a future "webauthn_prf" method.
 *
 * Lifecycle:
 *  - PIN setup requires the master key in memory. The expected source is
 *    a freshly password-authenticated session. SSO-only / JIT users who
 *    never had a password cannot bootstrap a PIN; they need an admin to
 *    enrol them out-of-band (not implemented in this phase).
 *  - PIN unlock decrypts the wrapped master key and feeds it to the
 *    existing generateUserSessionKey() so the rest of ITFlow's credential
 *    decrypt code keeps working.
 *  - Failed attempts are throttled per method: 5 strikes locks the method
 *    for 15 minutes. The legitimate user can wait or use another method.
 */

const VAULT_PIN_MIN_LENGTH    = 8;
const VAULT_LOCKOUT_THRESHOLD = 5;
const VAULT_LOCKOUT_MINUTES   = 15;

function vaultListMethods(int $user_id, mysqli $mysqli): array
{
    // Returns [] if the table does not yet exist (pre-migration state).
    try {
        $user_id = intval($user_id);
        $rs = mysqli_query(
            $mysqli,
            "SELECT method_id, method_type, label, failed_attempts, locked_until,
                    created_at, last_used_at
             FROM user_vault_unlock_methods
             WHERE user_id = $user_id
             ORDER BY method_type ASC, created_at ASC"
        );
        $out = [];
        if ($rs) {
            while ($row = mysqli_fetch_assoc($rs)) {
                $out[] = $row;
            }
        }
        return $out;
    } catch (Throwable $e) {
        return [];
    }
}

function vaultUserHasMethod(int $user_id, string $method_type, mysqli $mysqli): bool
{
    // Returns false if the table does not yet exist.
    try {
        $user_id = intval($user_id);
        $type_e  = mysqli_real_escape_string($mysqli, $method_type);
        $row = mysqli_fetch_assoc(mysqli_query(
            $mysqli,
            "SELECT COUNT(*) AS n
             FROM user_vault_unlock_methods
             WHERE user_id = $user_id AND method_type = '$type_e'"
        ));
        return $row && intval($row['n']) > 0;
    } catch (Throwable $e) {
        return false;
    }
}

/**
 * Wrap the master key (and optionally the user's privkey) under a
 * PIN-derived KEK and store as a 'pin' unlock method row.
 *
 * Phase 11: when $privkey is provided, it is wrapped under the same
 * PIN KEK (different IV) and stored alongside. This allows
 * vault_unlock.php to push BOTH master_key and privkey to the
 * session after a successful PIN unlock — preserving phase-10
 * compartmentalisation across SSO+PIN sign-ins.
 *
 * @return int the new method_id, or 0 on failure
 */
function vaultSetPin(int $user_id, #[\SensitiveParameter] string $master_key, ?string $privkey, #[\SensitiveParameter] string $pin, string $label, mysqli $mysqli): int
{
    if (strlen($pin) < VAULT_PIN_MIN_LENGTH) {
        throw new RuntimeException('PIN is too short (minimum ' . VAULT_PIN_MIN_LENGTH . ' characters)');
    }
    if ($master_key === '') {
        throw new RuntimeException('master key is empty');
    }

    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $kek  = deriveKekArgon2id($pin, $salt);

    $blob_master  = cryptoEncryptV2($master_key, $kek);
    $blob_privkey = ($privkey !== null && $privkey !== '')
        ? cryptoEncryptV2($privkey, $kek)
        : null;
    sodium_memzero($kek);

    $salt_b64        = base64_encode($salt);
    $wrapped_master  = base64_encode($blob_master);
    $wrapped_privkey = $blob_privkey !== null ? base64_encode($blob_privkey) : null;

    $salt_e          = mysqli_real_escape_string($mysqli, $salt_b64);
    $wrapped_e       = mysqli_real_escape_string($mysqli, $wrapped_master);
    $wrapped_priv_e  = $wrapped_privkey !== null
        ? "'" . mysqli_real_escape_string($mysqli, $wrapped_privkey) . "'"
        : 'NULL';
    $label_e         = mysqli_real_escape_string($mysqli, $label !== '' ? $label : 'Vault PIN');
    $user_id         = intval($user_id);

    // One PIN per user — replace if exists
    mysqli_query(
        $mysqli,
        "DELETE FROM user_vault_unlock_methods
         WHERE user_id = $user_id AND method_type = 'pin'"
    );

    mysqli_query(
        $mysqli,
        "INSERT INTO user_vault_unlock_methods
         SET user_id = $user_id,
             method_type = 'pin',
             label = '$label_e',
             salt = '$salt_e',
             wrapped_master_key = '$wrapped_e',
             wrapped_privkey = $wrapped_priv_e,
             created_at = NOW()"
    );
    return intval(mysqli_insert_id($mysqli));
}

/**
 * Derive a 32-byte AES-256-GCM key from a WebAuthn PRF output.
 *
 * The PRF output is already 32 bytes of high-entropy hardware-bound material;
 * we HKDF-expand it with a domain label so the same authenticator + salt can
 * never collide with other use cases of the same PRF output.
 */
function vaultDeriveKekFromPrf(#[\SensitiveParameter] string $prf_output): string
{
    if (strlen($prf_output) !== 32) {
        throw new RuntimeException('vaultDeriveKekFromPrf: PRF output must be 32 bytes');
    }
    return hash_hkdf('sha256', $prf_output, 32, 'itflow-vault-prf-v1');
}

/**
 * Wrap the master key under a PRF-derived KEK and store as a webauthn_prf method.
 * Caller is responsible for providing the credential_id, public_key_pem, sign_count,
 * cose_alg and prf_salt produced by the WebAuthn registration ceremony.
 */
function vaultStorePrfMethod(
    int $user_id,
    #[\SensitiveParameter] string $master_key,
    ?string $privkey,
    #[\SensitiveParameter] string $prf_output,
    string $credential_id_b64,
    string $public_key_pem,
    int $cose_alg,
    int $sign_count,
    string $prf_salt_raw,
    string $label,
    mysqli $mysqli
): int {
    if (strlen($prf_salt_raw) !== 32) {
        throw new RuntimeException('vaultStorePrfMethod: prf_salt must be 32 bytes');
    }

    $kek            = vaultDeriveKekFromPrf($prf_output);
    $wrapped_master = cryptoEncryptV2($master_key, $kek);
    $wrapped_priv   = ($privkey !== null && $privkey !== '')
        ? cryptoEncryptV2($privkey, $kek)
        : null;
    sodium_memzero($kek);

    $wrapped_master_b64 = base64_encode($wrapped_master);
    $wrapped_priv_b64   = $wrapped_priv !== null ? base64_encode($wrapped_priv) : null;
    $prf_salt_b64       = base64_encode($prf_salt_raw);
    $label              = $label !== '' ? substr($label, 0, 100) : 'Hardware unlock';

    $stmt = mysqli_prepare($mysqli, "
        INSERT INTO user_vault_unlock_methods
        (user_id, method_type, label, salt, wrapped_master_key, wrapped_privkey,
         credential_id, public_key, sign_count, prf_salt, created_at)
        VALUES (?, 'webauthn_prf', ?, '', ?, ?, ?, ?, ?, ?, NOW())
    ");
    if (!$stmt) {
        throw new RuntimeException('vaultStorePrfMethod: prepare failed');
    }
    // positions:  user_id, label, wrapped_master, wrapped_priv, cred_id, pubkey, sign_count, prf_salt
    //             i        s      s               s             s        s       i           s
    mysqli_stmt_bind_param(
        $stmt,
        'isssssis',
        $user_id, $label, $wrapped_master_b64, $wrapped_priv_b64,
        $credential_id_b64, $public_key_pem, $sign_count, $prf_salt_b64
    );
    mysqli_stmt_execute($stmt);
    $insert_id = mysqli_insert_id($mysqli);
    mysqli_stmt_close($stmt);
    return intval($insert_id);
}

/**
 * Look up a PRF method by credential id (base64url) and user id.
 */
function vaultFindPrfMethodByCredentialId(int $user_id, string $credential_id_b64, mysqli $mysqli): ?array
{
    $cred_e  = mysqli_real_escape_string($mysqli, $credential_id_b64);
    $user_id = intval($user_id);
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT method_id, label, wrapped_master_key, credential_id,
                public_key, sign_count, prf_salt,
                failed_attempts, locked_until
         FROM user_vault_unlock_methods
         WHERE user_id = $user_id
           AND method_type = 'webauthn_prf'
           AND credential_id = '$cred_e'
         LIMIT 1"
    ));
    return $row ?: null;
}

/**
 * Unlock the vault using a PRF output (after the assertion has been verified).
 * Phase 11: returns ['master' => ..., 'privkey' => ?...] when the privkey is
 * also wrapped in this method's row. The wrapper vaultTryUnlockWithPrf()
 * preserves the legacy single-string return.
 */
function vaultUnlockWithPrf(int $method_id, #[\SensitiveParameter] string $prf_output, mysqli $mysqli): ?array
{
    $method_id = intval($method_id);
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT wrapped_master_key, wrapped_privkey, failed_attempts, locked_until
         FROM user_vault_unlock_methods
         WHERE method_id = $method_id AND method_type = 'webauthn_prf'
         LIMIT 1"
    ));
    if (!$row || vaultIsLocked($row)) {
        return null;
    }
    $wrapped = base64_decode($row['wrapped_master_key'], true);
    if ($wrapped === false) {
        return null;
    }
    try {
        $kek    = vaultDeriveKekFromPrf($prf_output);
        $master = cryptoDecryptV2($wrapped, $kek);

        $privkey = null;
        if (!empty($row['wrapped_privkey'])) {
            $blob_priv = base64_decode($row['wrapped_privkey'], true);
            if ($blob_priv !== false) {
                try {
                    $privkey = cryptoDecryptV2($blob_priv, $kek);
                } catch (Throwable $e) {
                    error_log("vaultUnlockWithPrf: privkey unwrap failed for method_id=$method_id");
                }
            }
        }
        sodium_memzero($kek);
    } catch (Throwable $e) {
        $new_attempts = intval($row['failed_attempts']) + 1;
        if ($new_attempts >= VAULT_LOCKOUT_THRESHOLD) {
            mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
                SET failed_attempts = $new_attempts,
                    locked_until = DATE_ADD(NOW(), INTERVAL " . VAULT_LOCKOUT_MINUTES . " MINUTE)
                WHERE method_id = $method_id");
        } else {
            mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
                SET failed_attempts = $new_attempts WHERE method_id = $method_id");
        }
        return null;
    }
    mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
        SET failed_attempts = 0, locked_until = NULL, last_used_at = NOW()
        WHERE method_id = $method_id");
    return ['master' => $master, 'privkey' => $privkey];
}

// Backward-compatible thin wrapper.
function vaultTryUnlockWithPrf(int $method_id, #[\SensitiveParameter] string $prf_output, mysqli $mysqli): ?string
{
    $r = vaultUnlockWithPrf($method_id, $prf_output, $mysqli);
    return $r === null ? null : $r['master'];
}

function vaultDeleteMethod(int $method_id, int $user_id, mysqli $mysqli): bool
{
    $method_id = intval($method_id);
    $user_id   = intval($user_id);
    mysqli_query(
        $mysqli,
        "DELETE FROM user_vault_unlock_methods
         WHERE method_id = $method_id AND user_id = $user_id"
    );
    return mysqli_affected_rows($mysqli) > 0;
}

function vaultIsLocked(array $method_row): bool
{
    if (empty($method_row['locked_until'])) {
        return false;
    }
    return strtotime($method_row['locked_until']) > time();
}

/**
 * Try to unlock the vault for $user_id using $pin.
 *
 * Phase 11: returns the unwrapped master key AND privkey (if present)
 * via the array form `vaultUnlockWithPin()`. The legacy
 * `vaultTryUnlockWithPin()` keeps the original signature for any
 * other caller — it forwards to the new function and discards the
 * privkey.
 *
 * Returns null on wrong PIN, locked method, or malformed row.
 * Wrong PIN attempts increment failed_attempts (may lock the method).
 */
function vaultUnlockWithPin(int $user_id, #[\SensitiveParameter] string $pin, mysqli $mysqli): ?array
{
    $user_id = intval($user_id);
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT method_id, salt, wrapped_master_key, wrapped_privkey,
                failed_attempts, locked_until
         FROM user_vault_unlock_methods
         WHERE user_id = $user_id AND method_type = 'pin'
         LIMIT 1"
    ));
    if (!$row) {
        return null;
    }
    if (vaultIsLocked($row)) {
        return null;
    }

    $method_id = intval($row['method_id']);
    $salt      = base64_decode($row['salt'], true);
    $wrapped   = base64_decode($row['wrapped_master_key'], true);
    if ($salt === false || $wrapped === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        return null;
    }

    try {
        $kek    = deriveKekArgon2id($pin, $salt);
        $master = cryptoDecryptV2($wrapped, $kek);

        $privkey = null;
        if (!empty($row['wrapped_privkey'])) {
            $blob_priv = base64_decode($row['wrapped_privkey'], true);
            if ($blob_priv !== false) {
                try {
                    $privkey = cryptoDecryptV2($blob_priv, $kek);
                } catch (Throwable $e) {
                    // Privkey ciphertext malformed but master succeeded.
                    // Continue without privkey; user falls back to shared
                    // master path until they re-enrol PIN.
                    error_log("vaultUnlockWithPin: privkey unwrap failed for method_id=$method_id");
                    $privkey = null;
                }
            }
        }
        sodium_memzero($kek);
    } catch (Throwable $e) {
        // Wrong PIN, or tampered ciphertext on master. Increment counter.
        $new_attempts = intval($row['failed_attempts']) + 1;
        if ($new_attempts >= VAULT_LOCKOUT_THRESHOLD) {
            mysqli_query(
                $mysqli,
                "UPDATE user_vault_unlock_methods
                 SET failed_attempts = $new_attempts,
                     locked_until = DATE_ADD(NOW(), INTERVAL " . VAULT_LOCKOUT_MINUTES . " MINUTE)
                 WHERE method_id = $method_id"
            );
        } else {
            mysqli_query(
                $mysqli,
                "UPDATE user_vault_unlock_methods
                 SET failed_attempts = $new_attempts
                 WHERE method_id = $method_id"
            );
        }
        return null;
    }

    mysqli_query(
        $mysqli,
        "UPDATE user_vault_unlock_methods
         SET failed_attempts = 0,
             locked_until = NULL,
             last_used_at = NOW()
         WHERE method_id = $method_id"
    );
    return ['master' => $master, 'privkey' => $privkey];
}

// Backward-compatible thin wrapper.
function vaultTryUnlockWithPin(int $user_id, #[\SensitiveParameter] string $pin, mysqli $mysqli): ?string
{
    $r = vaultUnlockWithPin($user_id, $pin, $mysqli);
    return $r === null ? null : $r['master'];
}

/**
 * Read the master key out of the current session if it is unlocked.
 * Returns null if there is no unlocked vault in this session.
 */
function vaultMasterKeyFromSession(): ?string
{
    if (empty($_SESSION['user_encryption_session_ciphertext'])
        || empty($_SESSION['user_encryption_session_iv'])
        || empty($_COOKIE['user_encryption_session_key'])) {
        return null;
    }
    $master = openssl_decrypt(
        $_SESSION['user_encryption_session_ciphertext'],
        'aes-128-cbc',
        $_COOKIE['user_encryption_session_key'],
        0,
        $_SESSION['user_encryption_session_iv']
    );
    return ($master === false || $master === '') ? null : $master;
}
