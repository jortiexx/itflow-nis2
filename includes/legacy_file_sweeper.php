<?php
/*
 * Phase 15: opportunistic legacy file encryption sweeper.
 *
 * Phase 13 added at-rest encryption for files uploaded *after* its deploy.
 * Files that were already on disk stayed plaintext (file_encrypted = 0).
 * This sweeper re-encrypts them lazily.
 *
 * The crypto path requires the per-client master key, which is only
 * derivable when the vault is unlocked. So the sweep cannot run during
 * the DB migration (vault is locked then) — it runs opportunistically
 * after vault unlock, distributed across page loads, with a small
 * per-call time/file budget so no single page-load is slow.
 *
 * Per-client completion is tracked in client_master_keys.legacy_files_swept_at.
 * When NULL, the client may still have plaintext files. Once all that
 * client's files are file_encrypted = 1, we set the timestamp and never
 * scan that client again.
 *
 * Public entry points:
 *   sweepLegacyFilesForClient($client_id, $mysqli, $limit, $time_budget_seconds)
 *   sweepLegacyFilesOpportunistic($mysqli, $session_user_id, $session_is_admin, $time_budget_seconds)
 */

if (!function_exists('sweepLegacyFilesForClient')) {

    /**
     * Has the schema been migrated to the version that introduced the
     * file-encryption columns (DB 2.4.4.10)? If not, every helper in this
     * file is a no-op — there's nothing for us to sweep yet.
     *
     * Cached in a static after the first probe.
     */
    function legacyFileSweeperSchemaReady(mysqli $mysqli): bool
    {
        static $ready = null;
        if ($ready !== null) return $ready;
        try {
            $r = mysqli_fetch_assoc(mysqli_query($mysqli,
                "SHOW COLUMNS FROM files LIKE 'file_encrypted'"));
            if (!$r) {
                $ready = false;
                return $ready;
            }
            $r2 = mysqli_fetch_assoc(mysqli_query($mysqli,
                "SHOW COLUMNS FROM client_master_keys LIKE 'legacy_files_swept_at'"));
            $ready = (bool)$r2;
        } catch (Throwable $e) {
            $ready = false;
        }
        return $ready;
    }

    /**
     * How many plaintext files are still on disk that THIS user can sweep
     * (admin = all clients; user with grants = granted clients only;
     * user without any grants = unrestricted default).
     *
     * Cheap COUNT — used by the migration UI to draw the progress bar
     * and by load_user_session.php to decide whether to redirect.
     *
     * Returns 0 (and never errors out) if the schema is not yet migrated
     * to 2.4.4.11 — the redirect therefore won't fire on a stale DB.
     */
    function legacyFilesPendingForUser(mysqli $mysqli, int $user_id, bool $is_admin): int
    {
        if (!legacyFileSweeperSchemaReady($mysqli)) {
            return 0;
        }
        $user_id = intval($user_id);

        try {
            $access_clause = '';
            if (!$is_admin) {
                $r = mysqli_fetch_assoc(mysqli_query($mysqli,
                    "SELECT COUNT(*) AS n FROM user_client_permissions
                     WHERE user_id = $user_id"));
                if ($r && intval($r['n']) > 0) {
                    $access_clause = "AND files.file_client_id IN (
                        SELECT client_id FROM user_client_permissions
                        WHERE user_id = $user_id
                    )";
                }
            }

            $r = mysqli_fetch_assoc(mysqli_query($mysqli,
                "SELECT COUNT(*) AS n
                 FROM files
                 LEFT JOIN client_master_keys cmk ON cmk.client_id = files.file_client_id
                 WHERE files.file_encrypted = 0
                   AND files.file_archived_at IS NULL
                   AND (cmk.legacy_files_swept_at IS NULL OR cmk.client_id IS NULL)
                   $access_clause"));
            return $r ? intval($r['n']) : 0;
        } catch (Throwable $e) {
            return 0;
        }
    }


    /**
     * Encrypt up to $limit plaintext files for one client.
     *
     * Returns ['encrypted' => N, 'failed' => M, 'remaining' => K, 'completed' => bool].
     * If the per-client master cannot be derived (vault locked, no grant,
     * etc.), returns ['encrypted' => 0, 'reason' => 'no_master_key'].
     */
    function sweepLegacyFilesForClient(int $client_id, mysqli $mysqli, int $limit = 25, float $time_budget_seconds = 1.0): array
    {
        $client_id = intval($client_id);
        if ($client_id <= 0) {
            return ['encrypted' => 0, 'failed' => 0, 'remaining' => 0, 'completed' => false, 'reason' => 'invalid_client'];
        }
        if (!legacyFileSweeperSchemaReady($mysqli)) {
            return ['encrypted' => 0, 'failed' => 0, 'remaining' => 0, 'completed' => false, 'reason' => 'schema_not_migrated'];
        }

        require_once __DIR__ . '/file_storage.php';
        require_once __DIR__ . '/security_audit.php';

        // Derive the per-client master key. Prefer the per-user grant.
        $client_master = function_exists('getClientMasterKeyViaGrant')
            ? getClientMasterKeyViaGrant($client_id, $mysqli)
            : null;
        if ($client_master === null) {
            $client_master = ensureClientMasterKey($client_id, $mysqli);
        }
        if ($client_master === null) {
            return ['encrypted' => 0, 'failed' => 0, 'remaining' => -1, 'completed' => false, 'reason' => 'no_master_key'];
        }

        $key32 = expandMasterKeyToAes256($client_master);
        sodium_memzero($client_master);

        // Pull a small batch of plaintext files for this client.
        $candidates = [];
        $limit_i = max(1, intval($limit));
        $sql = "SELECT file_id, file_reference_name, file_sha256, file_mime_verified, file_mime_type
                FROM files
                WHERE file_client_id = $client_id
                  AND file_encrypted = 0
                  AND file_archived_at IS NULL
                ORDER BY file_id ASC
                LIMIT $limit_i";
        $res = mysqli_query($mysqli, $sql);
        while ($res && ($r = mysqli_fetch_assoc($res))) {
            $candidates[] = $r;
        }

        $encrypted = 0;
        $failed    = 0;
        $started   = microtime(true);

        foreach ($candidates as $c) {
            // Time-budget guard.
            if ((microtime(true) - $started) > $time_budget_seconds) {
                break;
            }

            $file_id = intval($c['file_id']);
            $ref     = (string)$c['file_reference_name'];
            $disk_path = __DIR__ . "/../uploads/clients/$client_id/" . basename($ref);

            if (!is_file($disk_path) || !is_readable($disk_path)) {
                // File missing on disk. Count how many times we've already
                // flagged this row — after the third miss we soft-archive it
                // so it stops re-entering the sweep queue (otherwise a single
                // ghost row keeps a client permanently "incomplete" and the
                // first-login migration UI loops forever).
                $miss_row = mysqli_fetch_assoc(mysqli_query($mysqli,
                    "SELECT COUNT(*) AS n FROM security_audit_log
                     WHERE event_type = 'file.migrate.missing_on_disk'
                       AND target_type = 'file'
                       AND target_id   = $file_id"));
                $prior_misses = $miss_row ? intval($miss_row['n']) : 0;

                securityAudit('file.migrate.missing_on_disk', [
                    'target_type' => 'file',
                    'target_id'   => $file_id,
                    'metadata'    => ['client_id' => $client_id, 'reference' => $ref],
                ]);

                if ($prior_misses + 1 >= 3) {
                    mysqli_query($mysqli,
                        "UPDATE files SET file_archived_at = NOW()
                         WHERE file_id = $file_id AND file_archived_at IS NULL");
                    securityAudit('file.migrate.ghost_row_archived', [
                        'target_type' => 'file',
                        'target_id'   => $file_id,
                        'metadata'    => [
                            'client_id'    => $client_id,
                            'reference'    => $ref,
                            'misses_total' => $prior_misses + 1,
                        ],
                    ]);
                }
                $failed++;
                continue;
            }

            // Race-safe lock. If another worker is already encrypting this
            // file (rare but possible with multiple admins logging in at
            // the same time), skip silently — the other worker will mark
            // it encrypted = 1 and we won't see it again.
            $fh = @fopen($disk_path, 'r+b');
            if (!$fh) {
                $failed++;
                continue;
            }
            if (!flock($fh, LOCK_EX | LOCK_NB)) {
                fclose($fh);
                continue;
            }

            $plaintext = stream_get_contents($fh);
            if ($plaintext === false) {
                flock($fh, LOCK_UN);
                fclose($fh);
                $failed++;
                continue;
            }

            // Hash the plaintext so future downloads can verify integrity.
            $sha256 = fileHashSha256($plaintext);

            // Server-side MIME so we can populate file_mime_verified for
            // rows that pre-date that column being filled. Use finfo_buffer
            // on the bytes we already read — finfo_file($disk_path) would
            // race with the LOCK_EX we hold on $fh (Windows uses mandatory
            // locking, so a second open of the same path returns 'Permission
            // denied' and PHP emits warnings that leak into the JSON AJAX
            // response, breaking the migration progress UI).
            $detected_mime = null;
            if (function_exists('finfo_open')) {
                $f = finfo_open(FILEINFO_MIME_TYPE);
                if ($f) {
                    $d = @finfo_buffer($f, $plaintext);
                    if ($d) $detected_mime = $d;
                    finfo_close($f);
                }
            }
            $mime_for_row = $detected_mime ?: ($c['file_mime_verified'] ?? $c['file_mime_type'] ?? null);

            // Encrypt with the same primitive as fresh uploads.
            $iv  = random_bytes(12);
            $tag = '';
            $ct  = openssl_encrypt(
                $plaintext, 'aes-256-gcm', $key32,
                OPENSSL_RAW_DATA, $iv, $tag, '', 16
            );
            sodium_memzero($plaintext);
            if ($ct === false) {
                flock($fh, LOCK_UN);
                fclose($fh);
                $failed++;
                continue;
            }

            // Write ciphertext over the locked handle.
            if (ftruncate($fh, 0) === false || rewind($fh) === false || fwrite($fh, $ct) === false) {
                flock($fh, LOCK_UN);
                fclose($fh);
                $failed++;
                continue;
            }
            fflush($fh);

            // Persist the new metadata via prepared statement (binary-safe
            // for the VARBINARY columns).
            $stmt = mysqli_prepare($mysqli,
                "UPDATE files
                 SET file_encrypted        = 1,
                     file_encryption_iv    = ?,
                     file_encryption_tag   = ?,
                     file_sha256           = ?,
                     file_mime_verified    = COALESCE(file_mime_verified, ?)
                 WHERE file_id = ?");
            mysqli_stmt_bind_param($stmt, 'ssssi',
                $iv, $tag, $sha256, $mime_for_row, $file_id);
            $ok = mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            if ($ok) {
                $encrypted++;
                securityAudit('file.migrate.encrypted', [
                    'target_type' => 'file',
                    'target_id'   => $file_id,
                    'metadata'    => ['client_id' => $client_id],
                ]);
            } else {
                // Best-effort: if the UPDATE failed, the file is now
                // ciphertext on disk but the DB still says plaintext.
                // Roll back the disk write so the download path stays
                // consistent.
                $rb = openssl_decrypt(
                    $ct, 'aes-256-gcm', $key32, OPENSSL_RAW_DATA, $iv, $tag
                );
                if ($rb !== false) {
                    ftruncate($fh, 0);
                    rewind($fh);
                    fwrite($fh, $rb);
                    fflush($fh);
                }
                $failed++;
            }
            flock($fh, LOCK_UN);
            fclose($fh);
        }

        sodium_memzero($key32);

        // Are there still rows for this client to do?
        $remaining_row = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT COUNT(*) AS n FROM files
             WHERE file_client_id = $client_id
               AND file_encrypted = 0
               AND file_archived_at IS NULL"));
        $remaining = $remaining_row ? intval($remaining_row['n']) : 0;
        $completed = ($remaining === 0);

        if ($completed) {
            mysqli_query($mysqli,
                "UPDATE client_master_keys
                 SET legacy_files_swept_at = NOW()
                 WHERE client_id = $client_id");
            securityAudit('file.migrate.client_complete', [
                'target_type' => 'client',
                'target_id'   => $client_id,
                'metadata'    => ['encrypted_this_run' => $encrypted, 'failed_this_run' => $failed],
            ]);
        }

        return [
            'encrypted' => $encrypted,
            'failed'    => $failed,
            'remaining' => $remaining,
            'completed' => $completed,
        ];
    }

    /**
     * Pick one client this user has access to + plaintext files remaining
     * + try a small batch. Designed to be called once per session per
     * hour with a tight time budget.
     *
     * Returns the result of sweepLegacyFilesForClient, or
     * ['encrypted' => 0, 'reason' => '...'] if nothing to do or no
     * accessible clients.
     */
    function sweepLegacyFilesOpportunistic(mysqli $mysqli, int $session_user_id, bool $session_is_admin, float $time_budget_seconds = 1.0): array
    {
        if (!legacyFileSweeperSchemaReady($mysqli)) {
            return ['encrypted' => 0, 'reason' => 'schema_not_migrated'];
        }

        // Find a client that still has plaintext files. Restrict to
        // clients the user can access:
        //   - admin: any client
        //   - user with explicit grants: only their granted clients
        //   - user with no grants at all: any client (unrestricted default)
        $session_user_id = intval($session_user_id);

        $access_clause = '';
        if (!$session_is_admin) {
            $r = mysqli_fetch_assoc(mysqli_query($mysqli,
                "SELECT COUNT(*) AS n FROM user_client_permissions
                 WHERE user_id = $session_user_id"));
            if ($r && intval($r['n']) > 0) {
                $access_clause = "AND files.file_client_id IN (
                    SELECT client_id FROM user_client_permissions
                    WHERE user_id = $session_user_id
                )";
            }
        }

        // Pick the lowest client_id that still has unencrypted files and
        // hasn't been marked complete.
        $sql = "SELECT files.file_client_id AS client_id
                FROM files
                LEFT JOIN client_master_keys cmk ON cmk.client_id = files.file_client_id
                WHERE files.file_encrypted = 0
                  AND files.file_archived_at IS NULL
                  AND (cmk.legacy_files_swept_at IS NULL OR cmk.client_id IS NULL)
                  $access_clause
                GROUP BY files.file_client_id
                ORDER BY files.file_client_id ASC
                LIMIT 1";
        $r = mysqli_fetch_assoc(mysqli_query($mysqli, $sql));
        if (!$r || empty($r['client_id'])) {
            return ['encrypted' => 0, 'reason' => 'nothing_to_do'];
        }

        return sweepLegacyFilesForClient(
            intval($r['client_id']), $mysqli, 25, $time_budget_seconds
        );
    }
}
