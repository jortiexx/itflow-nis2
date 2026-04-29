<?php
/*
 * Magic-link vault enrolment for JIT-provisioned (SSO-only) agents.
 *
 * The bootstrap problem: a JIT-provisioned agent is created during the
 * first SSO callback. They never had a password, so the master key was
 * never wrapped under any factor for them. They also cannot enrol a vault
 * PIN or PRF themselves because that requires the master key in their
 * session — and SSO does not provide one.
 *
 * Magic link flow:
 *   1. An admin (with vault unlocked) clicks "Send vault enrolment" for the
 *      target user. Server generates a random token, derives a one-shot
 *      KEK from it via Argon2id, and wraps the master key under that KEK.
 *      Token, salt, wrapped master key are stored in pending_vault_enrolments
 *      with a one-hour expiry.
 *   2. The target user receives the link by email (Entra-authenticated
 *      mailbox is the implicit second factor — only the legitimate user can
 *      open the email).
 *   3. The user signs in via SSO, then opens the link. The endpoint reads
 *      the token, recovers the master key, and shows the standard PIN /
 *      WebAuthn-PRF enrolment UI. On enrolment success, the pending row is
 *      consumed and the magic link is no longer redeemable.
 *
 * Threat model:
 *   - Email interception: attacker would also need to be SSO-authenticated
 *     as the target user. Entra MFA + conditional access blocks this.
 *   - Replay: token is single-use; consumed_at is set atomically before
 *     enrolment proceeds.
 *   - Stale links: 1-hour expiry by default.
 *   - Admin compromise: an attacker who is logged in as an ITFlow admin
 *     with the vault unlocked could already enrol a method directly; magic
 *     links do not lower that bar.
 */

const VAULT_ENROLMENT_TOKEN_BYTES = 32;
const VAULT_ENROLMENT_TTL_SECONDS = 3600;  // 1 hour

if (!function_exists('vaultIssueEnrolmentToken')) {

    /**
     * Issue a magic-link enrolment token for $user_id. Caller must already
     * have the master key in their session (admin or otherwise).
     *
     * @return string  The token (raw bytes, base64url-safe). Caller is
     *                 responsible for sending it to the target user via
     *                 a trusted channel.
     */
    function vaultIssueEnrolmentToken(int $user_id, int $created_by_user_id, mysqli $mysqli): string
    {
        $master = vaultMasterKeyFromSession();
        if ($master === null) {
            throw new RuntimeException('vaultIssueEnrolmentToken: vault is locked');
        }

        $token_raw = random_bytes(VAULT_ENROLMENT_TOKEN_BYTES);
        $salt      = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

        $token_b64 = rtrim(strtr(base64_encode($token_raw), '+/', '-_'), '=');
        $token_hash = password_hash($token_b64, PASSWORD_BCRYPT);

        $kek = deriveKekArgon2id($token_b64, $salt);
        $wrapped = cryptoEncryptV2($master, $kek);
        sodium_memzero($kek);

        $wrapped_b64 = base64_encode($wrapped);
        $salt_b64    = base64_encode($salt);

        $expires_at = date('Y-m-d H:i:s', time() + VAULT_ENROLMENT_TTL_SECONDS);

        // Invalidate any prior pending enrolments for this user — only the
        // most recent magic link should be redeemable.
        mysqli_query($mysqli,
            "UPDATE pending_vault_enrolments SET consumed_at = NOW()
             WHERE user_id = $user_id AND consumed_at IS NULL");

        $stmt = mysqli_prepare($mysqli, "
            INSERT INTO pending_vault_enrolments
            (user_id, token_hash, wrapped_master_key, salt,
             created_by_user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, NOW(), ?)
        ");
        if (!$stmt) {
            throw new RuntimeException('vaultIssueEnrolmentToken: prepare failed');
        }
        mysqli_stmt_bind_param(
            $stmt,
            'isssis',
            $user_id, $token_hash, $wrapped_b64, $salt_b64,
            $created_by_user_id, $expires_at
        );
        if (!mysqli_stmt_execute($stmt)) {
            mysqli_stmt_close($stmt);
            throw new RuntimeException('vaultIssueEnrolmentToken: insert failed');
        }
        mysqli_stmt_close($stmt);

        return $token_b64;
    }
}

if (!function_exists('vaultRedeemEnrolmentToken')) {

    /**
     * Redeem a magic-link token and recover the wrapped master key.
     * On success returns the master key bytes; consumes the row atomically.
     *
     * @return string|null  Master key bytes on success, null on
     *                      not-found / expired / mismatch / already-consumed.
     */
    function vaultRedeemEnrolmentToken(int $user_id, #[\SensitiveParameter] string $token_b64, mysqli $mysqli): ?string
    {
        // Pull the most recent unconsumed pending enrolment for this user.
        $row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT enrolment_id, token_hash, wrapped_master_key, salt, expires_at
             FROM pending_vault_enrolments
             WHERE user_id = $user_id AND consumed_at IS NULL
             ORDER BY enrolment_id DESC LIMIT 1"));
        if (!$row) {
            return null;
        }
        if (strtotime($row['expires_at']) < time()) {
            return null;
        }
        if (!password_verify($token_b64, $row['token_hash'])) {
            return null;
        }

        // Atomically claim this row — fail closed if someone else consumed it.
        $eid = intval($row['enrolment_id']);
        mysqli_query($mysqli,
            "UPDATE pending_vault_enrolments
             SET consumed_at = NOW()
             WHERE enrolment_id = $eid AND consumed_at IS NULL");
        if (mysqli_affected_rows($mysqli) === 0) {
            return null;
        }

        $salt    = base64_decode($row['salt'], true);
        $wrapped = base64_decode($row['wrapped_master_key'], true);
        if ($salt === false || $wrapped === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            return null;
        }

        try {
            $kek = deriveKekArgon2id($token_b64, $salt);
            $master = cryptoDecryptV2($wrapped, $kek);
            sodium_memzero($kek);
            return $master;
        } catch (Throwable $e) {
            return null;
        }
    }
}
