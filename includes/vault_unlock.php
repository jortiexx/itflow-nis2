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
                    created_at, last_used_at, disabled_at, disabled_by_user_id,
                    aaguid, backup_eligible, backup_state, transports, kdf_version
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

/**
 * Phase 18: kill-switch — disable a single unlock method without deleting
 * it (preserves audit trail). Re-enabling is a separate operation.
 */
function vaultDisableMethod(int $method_id, int $owner_user_id, int $actor_user_id, mysqli $mysqli): bool
{
    $method_id     = intval($method_id);
    $owner_user_id = intval($owner_user_id);
    $actor_user_id = intval($actor_user_id);
    mysqli_query(
        $mysqli,
        "UPDATE user_vault_unlock_methods
         SET disabled_at = NOW(),
             disabled_by_user_id = $actor_user_id
         WHERE method_id = $method_id
           AND user_id = $owner_user_id
           AND disabled_at IS NULL"
    );
    return mysqli_affected_rows($mysqli) > 0;
}

function vaultEnableMethod(int $method_id, int $owner_user_id, mysqli $mysqli): bool
{
    $method_id     = intval($method_id);
    $owner_user_id = intval($owner_user_id);
    mysqli_query(
        $mysqli,
        "UPDATE user_vault_unlock_methods
         SET disabled_at = NULL,
             disabled_by_user_id = NULL,
             failed_attempts = 0,
             locked_until = NULL
         WHERE method_id = $method_id
           AND user_id = $owner_user_id"
    );
    return mysqli_affected_rows($mysqli) > 0;
}

/**
 * Admin operation: force re-enrolment of every unlock method for a user.
 * The user must sign in with their account password (or be re-bootstrapped
 * by an admin via vault_enrol) before they can use the vault again.
 */
function vaultForceReenrol(int $owner_user_id, int $actor_user_id, mysqli $mysqli): int
{
    $owner_user_id = intval($owner_user_id);
    mysqli_query(
        $mysqli,
        "DELETE FROM user_vault_unlock_methods WHERE user_id = $owner_user_id"
    );
    return mysqli_affected_rows($mysqli);
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

    // Phase 18: bind wrap to user via AAD; tracked by kdf_version=2.
    $aad_master   = vaultWrapAad($user_id, 'master');
    $aad_privkey  = vaultWrapAad($user_id, 'privkey');
    $blob_master  = cryptoEncryptV2($master_key, $kek, $aad_master);
    $blob_privkey = ($privkey !== null && $privkey !== '')
        ? cryptoEncryptV2($privkey, $kek, $aad_privkey)
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
             kdf_version = 2,
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
 *
 * kdf_version=1 (legacy): info = "itflow-vault-prf-v1"
 * kdf_version=2 (current): info adds user binding +
 *   uses the per-row prf_salt as HKDF salt so re-enrolment with the
 *   same authenticator yields a different KEK.
 */
function vaultDeriveKekFromPrf(
    #[\SensitiveParameter] string $prf_output,
    int $kdf_version = 2,
    int $user_id = 0,
    string $prf_salt_raw = ''
): string {
    if (strlen($prf_output) !== 32) {
        throw new RuntimeException('vaultDeriveKekFromPrf: PRF output must be 32 bytes');
    }
    if ($kdf_version <= 1) {
        return hash_hkdf('sha256', $prf_output, 32, 'itflow-vault-prf-v1');
    }
    $info = 'itflow-vault-prf-v2|user=' . $user_id;
    return hash_hkdf('sha256', $prf_output, 32, $info, $prf_salt_raw);
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
    mysqli $mysqli,
    array $authenticator_metadata = []
): int {
    if (strlen($prf_salt_raw) !== 32) {
        throw new RuntimeException('vaultStorePrfMethod: prf_salt must be 32 bytes');
    }

    $kek            = vaultDeriveKekFromPrf($prf_output, 2, $user_id, $prf_salt_raw);
    $aad_master     = vaultWrapAad($user_id, 'master');
    $aad_privkey    = vaultWrapAad($user_id, 'privkey');
    $wrapped_master = cryptoEncryptV2($master_key, $kek, $aad_master);
    $wrapped_priv   = ($privkey !== null && $privkey !== '')
        ? cryptoEncryptV2($privkey, $kek, $aad_privkey)
        : null;
    sodium_memzero($kek);

    $wrapped_master_b64 = base64_encode($wrapped_master);
    $wrapped_priv_b64   = $wrapped_priv !== null ? base64_encode($wrapped_priv) : null;
    $prf_salt_b64       = base64_encode($prf_salt_raw);
    $label              = $label !== '' ? substr($label, 0, 100) : 'Hardware unlock';
    $kdf_version        = 2;

    // Phase 18: capture FIDO2 metadata for policy + troubleshooting.
    $aaguid          = isset($authenticator_metadata['aaguid'])          ? (string)$authenticator_metadata['aaguid']     : null;
    $backup_eligible = isset($authenticator_metadata['backup_eligible']) ? intval($authenticator_metadata['backup_eligible']) : null;
    $backup_state    = isset($authenticator_metadata['backup_state'])    ? intval($authenticator_metadata['backup_state'])    : null;
    $transports      = isset($authenticator_metadata['transports'])      ? substr((string)$authenticator_metadata['transports'], 0, 64) : null;

    $stmt = mysqli_prepare($mysqli, "
        INSERT INTO user_vault_unlock_methods
        (user_id, method_type, label, salt, wrapped_master_key, wrapped_privkey,
         credential_id, public_key, sign_count, prf_salt, cose_alg, kdf_version,
         aaguid, backup_eligible, backup_state, transports, created_at)
        VALUES (?, 'webauthn_prf', ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");
    if (!$stmt) {
        throw new RuntimeException('vaultStorePrfMethod: prepare failed');
    }
    // positions: user_id, label, wrapped_master, wrapped_priv, cred_id, pubkey, sign_count,
    //            prf_salt, cose_alg, kdf_version, aaguid, be, bs, transports
    //            i,        s,        s,         s,            s,       s,      i,
    //            s,        i,        i,         s,      i,  i,  s
    mysqli_stmt_bind_param(
        $stmt,
        'isssssisiisiis',
        $user_id, $label, $wrapped_master_b64, $wrapped_priv_b64,
        $credential_id_b64, $public_key_pem, $sign_count, $prf_salt_b64,
        $cose_alg, $kdf_version,
        $aaguid, $backup_eligible, $backup_state, $transports
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
        "SELECT method_id, user_id, label, wrapped_master_key, credential_id,
                public_key, sign_count, prf_salt, cose_alg, kdf_version,
                failed_attempts, locked_until, disabled_at
         FROM user_vault_unlock_methods
         WHERE user_id = $user_id
           AND method_type = 'webauthn_prf'
           AND credential_id = '$cred_e'
           AND disabled_at IS NULL
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
        "SELECT user_id, wrapped_master_key, wrapped_privkey, prf_salt, kdf_version,
                failed_attempts, locked_until, disabled_at
         FROM user_vault_unlock_methods
         WHERE method_id = $method_id AND method_type = 'webauthn_prf'
         LIMIT 1"
    ));
    if (!$row || vaultIsLocked($row) || !empty($row['disabled_at'])) {
        return null;
    }
    if (vaultAccountSecondsUntilUnlock(intval($row['user_id']), $mysqli) > 0) {
        return null;
    }
    $wrapped = base64_decode($row['wrapped_master_key'], true);
    if ($wrapped === false) {
        return null;
    }
    $row_user_id    = intval($row['user_id']);
    $row_kdf        = intval($row['kdf_version'] ?? 1);
    $prf_salt_raw   = !empty($row['prf_salt']) ? base64_decode($row['prf_salt'], true) : '';
    if ($prf_salt_raw === false) $prf_salt_raw = '';

    try {
        // Try current KDF first; on failure, fall back to legacy KDF (lazy migration).
        $master  = null;
        $privkey = null;
        $unwrap_kdf = $row_kdf;

        foreach ([$row_kdf, ($row_kdf === 2 ? 1 : 2)] as $try_kdf) {
            try {
                $kek = vaultDeriveKekFromPrf($prf_output, $try_kdf, $row_user_id, $prf_salt_raw);
                $aad_master  = $try_kdf >= 2 ? vaultWrapAad($row_user_id, 'master')  : '';
                $aad_privkey = $try_kdf >= 2 ? vaultWrapAad($row_user_id, 'privkey') : '';
                $master = cryptoDecryptV2($wrapped, $kek, $aad_master);

                if (!empty($row['wrapped_privkey'])) {
                    $blob_priv = base64_decode($row['wrapped_privkey'], true);
                    if ($blob_priv !== false) {
                        try {
                            $privkey = cryptoDecryptV2($blob_priv, $kek, $aad_privkey);
                        } catch (Throwable $e) {
                            error_log("vaultUnlockWithPrf: privkey unwrap failed for method_id=$method_id");
                        }
                    }
                }
                sodium_memzero($kek);
                $unwrap_kdf = $try_kdf;
                break;
            } catch (Throwable $e) {
                if (isset($kek)) sodium_memzero($kek);
                continue;
            }
        }

        if ($master === null) {
            throw new RuntimeException('all KDF candidates failed');
        }
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
        vaultAccountRegisterFailure(intval($row['user_id']), $mysqli);
        return null;
    }

    // Lazy migration: if we unlocked via legacy KDF, re-wrap under the
    // current KDF + AAD and bump kdf_version. Best-effort — failure here
    // is non-fatal (user can still use the vault, we'll retry next time).
    if ($unwrap_kdf < 2) {
        try {
            $new_kek = vaultDeriveKekFromPrf($prf_output, 2, $row_user_id, $prf_salt_raw);
            $new_master_blob = cryptoEncryptV2($master, $new_kek, vaultWrapAad($row_user_id, 'master'));
            $new_priv_blob   = ($privkey !== null)
                ? cryptoEncryptV2($privkey, $new_kek, vaultWrapAad($row_user_id, 'privkey'))
                : null;
            sodium_memzero($new_kek);

            $new_master_b64 = mysqli_real_escape_string($mysqli, base64_encode($new_master_blob));
            $new_priv_sql   = $new_priv_blob !== null
                ? "'" . mysqli_real_escape_string($mysqli, base64_encode($new_priv_blob)) . "'"
                : 'wrapped_privkey';
            mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
                SET wrapped_master_key = '$new_master_b64',
                    wrapped_privkey    = $new_priv_sql,
                    kdf_version        = 2
                WHERE method_id = $method_id");
        } catch (Throwable $e) {
            error_log("vaultUnlockWithPrf: lazy migration failed for method_id=$method_id: " . $e->getMessage());
        }
    }

    mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
        SET failed_attempts = 0, locked_until = NULL, last_used_at = NOW()
        WHERE method_id = $method_id");
    vaultAccountClearFailures(intval($row['user_id']), $mysqli);
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
 * Phase 18: per-account lockout with exponential backoff.
 *
 * Independent of the per-method `locked_until` so an attacker cannot
 * sidestep the cap by rotating between PIN and PRF. Backoff seconds
 * = min(2^consecutive_failures, $cap), capped by config.
 *
 * Returns the seconds remaining until unlock, or 0 if not locked.
 */
function vaultAccountSecondsUntilUnlock(int $user_id, mysqli $mysqli): int
{
    $user_id = intval($user_id);
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT vault_locked_until FROM users WHERE user_id = $user_id LIMIT 1"
    ));
    if (!$row || empty($row['vault_locked_until'])) {
        return 0;
    }
    $remaining = strtotime($row['vault_locked_until']) - time();
    return $remaining > 0 ? $remaining : 0;
}

function vaultAccountRegisterFailure(int $user_id, mysqli $mysqli): int
{
    $user_id = intval($user_id);
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT vault_consecutive_failures FROM users WHERE user_id = $user_id LIMIT 1"
    ));
    $next = $row ? intval($row['vault_consecutive_failures']) + 1 : 1;

    $cap = intval($GLOBALS['config_vault_lockout_max_seconds'] ?? 3600);
    if ($cap < 1) $cap = 3600;
    // 2^n grows fast; clamp so we don't overflow.
    $exp = $next > 24 ? PHP_INT_MAX : (1 << $next);
    $delay = min($cap, $exp);

    mysqli_query(
        $mysqli,
        "UPDATE users
         SET vault_consecutive_failures = $next,
             vault_locked_until = DATE_ADD(NOW(), INTERVAL " . intval($delay) . " SECOND)
         WHERE user_id = $user_id"
    );
    return $delay;
}

function vaultAccountClearFailures(int $user_id, mysqli $mysqli): void
{
    $user_id = intval($user_id);
    mysqli_query(
        $mysqli,
        "UPDATE users
         SET vault_consecutive_failures = 0,
             vault_locked_until = NULL
         WHERE user_id = $user_id"
    );
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
    if (vaultAccountSecondsUntilUnlock($user_id, $mysqli) > 0) {
        return null;
    }
    $row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT method_id, salt, wrapped_master_key, wrapped_privkey, kdf_version,
                failed_attempts, locked_until, disabled_at
         FROM user_vault_unlock_methods
         WHERE user_id = $user_id AND method_type = 'pin'
         LIMIT 1"
    ));
    if (!$row || vaultIsLocked($row) || !empty($row['disabled_at'])) {
        return null;
    }

    $method_id = intval($row['method_id']);
    $salt      = base64_decode($row['salt'], true);
    $wrapped   = base64_decode($row['wrapped_master_key'], true);
    $row_kdf   = intval($row['kdf_version'] ?? 1);
    if ($salt === false || $wrapped === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
        return null;
    }

    try {
        $kek = deriveKekArgon2id($pin, $salt);

        $master  = null;
        $privkey = null;
        $unwrap_kdf = $row_kdf;

        // Try AAD-bound (kdf=2) first if row claims it, otherwise legacy.
        // Fall back to the other version on tag failure (lazy migration).
        foreach ([$row_kdf, ($row_kdf === 2 ? 1 : 2)] as $try_kdf) {
            try {
                $aad_master  = $try_kdf >= 2 ? vaultWrapAad($user_id, 'master')  : '';
                $aad_privkey = $try_kdf >= 2 ? vaultWrapAad($user_id, 'privkey') : '';
                $master = cryptoDecryptV2($wrapped, $kek, $aad_master);

                if (!empty($row['wrapped_privkey'])) {
                    $blob_priv = base64_decode($row['wrapped_privkey'], true);
                    if ($blob_priv !== false) {
                        try {
                            $privkey = cryptoDecryptV2($blob_priv, $kek, $aad_privkey);
                        } catch (Throwable $e) {
                            error_log("vaultUnlockWithPin: privkey unwrap failed for method_id=$method_id");
                            $privkey = null;
                        }
                    }
                }
                $unwrap_kdf = $try_kdf;
                break;
            } catch (Throwable $e) {
                continue;
            }
        }

        if ($master === null) {
            sodium_memzero($kek);
            throw new RuntimeException('all KDF candidates failed');
        }
    } catch (Throwable $e) {
        // Wrong PIN, or tampered ciphertext on master. Increment counters.
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
        vaultAccountRegisterFailure($user_id, $mysqli);
        return null;
    }

    // Lazy migration: re-wrap under AAD if row was legacy.
    if ($unwrap_kdf < 2) {
        try {
            $new_master_blob = cryptoEncryptV2($master, $kek, vaultWrapAad($user_id, 'master'));
            $new_priv_blob   = ($privkey !== null)
                ? cryptoEncryptV2($privkey, $kek, vaultWrapAad($user_id, 'privkey'))
                : null;
            $new_master_b64 = mysqli_real_escape_string($mysqli, base64_encode($new_master_blob));
            $new_priv_sql   = $new_priv_blob !== null
                ? "'" . mysqli_real_escape_string($mysqli, base64_encode($new_priv_blob)) . "'"
                : 'wrapped_privkey';
            mysqli_query($mysqli, "UPDATE user_vault_unlock_methods
                SET wrapped_master_key = '$new_master_b64',
                    wrapped_privkey    = $new_priv_sql,
                    kdf_version        = 2
                WHERE method_id = $method_id");
        } catch (Throwable $e) {
            error_log("vaultUnlockWithPin: lazy migration failed for method_id=$method_id: " . $e->getMessage());
        }
    }
    sodium_memzero($kek);

    mysqli_query(
        $mysqli,
        "UPDATE user_vault_unlock_methods
         SET failed_attempts = 0,
             locked_until = NULL,
             last_used_at = NOW()
         WHERE method_id = $method_id"
    );
    vaultAccountClearFailures($user_id, $mysqli);
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
 * Returns null if there is no unlocked vault in this session, or if the
 * session has been idle past the configured TTL (phase 18).
 */
function vaultMasterKeyFromSession(): ?string
{
    if (!vaultSessionStillFresh()) {
        return null;
    }
    if (!function_exists('sessionUnwrapMasterKey')) {
        return null;
    }
    $master = sessionUnwrapMasterKey();
    if ($master === null) {
        return null;
    }
    // Touch idle timer on every successful read so an active operator
    // never times out mid-session, but a closed laptop does.
    $_SESSION['vault_unlocked_at'] = time();
    return $master;
}

/**
 * Phase 18: vault idle TTL.
 *
 * Returns true if the session is unlocked and within the idle TTL.
 * Returns false (and clears vault state) if the session has been idle
 * past the configured threshold or never recorded an unlock timestamp.
 */
function vaultSessionStillFresh(): bool
{
    if (empty($_SESSION['vault_unlocked'])) {
        return false;
    }
    $unlocked_at = intval($_SESSION['vault_unlocked_at'] ?? 0);
    if ($unlocked_at <= 0) {
        // Pre-phase-18 session that never recorded a timestamp. Treat as
        // fresh once and let the caller's touch update the timestamp.
        return true;
    }
    $ttl = intval($GLOBALS['config_vault_idle_ttl_seconds'] ?? 1800);
    if ($ttl <= 0) $ttl = 1800;
    if ((time() - $unlocked_at) > $ttl) {
        $_SESSION['vault_unlocked'] = false;
        unset($_SESSION['vault_unlocked_at']);
        return false;
    }
    return true;
}

/**
 * Phase 18: step-up helper with its OWN freshness timer.
 *
 * Distinct from `vault_unlocked_at` (which is touched on every credential
 * read for idle-TTL tracking). `vault_step_up_at` is set ONLY when:
 *   - the user just unlocked the vault from cold (login, magic link)
 *   - the user re-typed PIN / re-tapped FIDO2 in response to a step-up
 *     redirect from this helper
 *
 * Default window: 300s. Within that window, repeated calls are no-ops so
 * an operator burst-revealing 30 credentials only types their PIN once.
 */
const VAULT_STEP_UP_DEFAULT_SECONDS = 300;

function vaultStepUpFresh(int $max_age_seconds = VAULT_STEP_UP_DEFAULT_SECONDS): bool
{
    if (empty($_SESSION['vault_unlocked'])) return false;
    $stamp = intval($_SESSION['vault_step_up_at'] ?? 0);
    if ($stamp <= 0) return false;
    return (time() - $stamp) <= $max_age_seconds;
}

function vaultStepUpRecord(): void
{
    $_SESSION['vault_step_up_at'] = time();
}

function requireFreshVaultUnlock(int $max_age_seconds = VAULT_STEP_UP_DEFAULT_SECONDS): void
{
    if (vaultStepUpFresh($max_age_seconds)) {
        return;
    }
    $return_to = $_SERVER['REQUEST_URI'] ?? '/';
    header('Location: /agent/vault_unlock.php?step_up=1&return_to=' . urlencode($return_to));
    exit;
}
