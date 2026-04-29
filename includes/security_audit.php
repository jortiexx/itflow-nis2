<?php
/*
 * Tamper-evident security audit log.
 *
 * Each event is appended to security_audit_log with a SHA-256 hash chain:
 *   entry_hash = SHA256(prev_hash || canonical_json(entry_fields))
 *
 * Verifying integrity is a pure walk: recompute each entry_hash and confirm
 * it matches the stored value, and that prev_hash equals the previous entry's
 * entry_hash. Any insertion/deletion/modification of a row breaks the chain
 * for that row and every row after it. See scripts/audit_verify.php.
 *
 * The chain does not protect against an attacker with full DB write access —
 * they could rebuild the chain. It protects against partial compromise
 * (selective row delete via SQL injection, accidental edits) and gives a
 * forensic anchor: at any point in time you can record the latest entry_hash
 * elsewhere (SIEM, cold storage, paper) and later prove no tampering up to
 * that point.
 *
 * Events are independent of the existing logs table: that one is a generic
 * application log; this one is the security-relevant subset, immutable by
 * convention and verifiable by hash chain.
 */

const SECURITY_AUDIT_NULL_HASH = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

if (!function_exists('securityAuditCanonicalize')) {

    /**
     * Build a deterministic JSON serialization of the entry fields used in
     * the hash chain. Keys must be in a fixed order so verification works
     * regardless of PHP's array iteration order.
     */
    function securityAuditCanonicalize(array $entry): string
    {
        $ordered = [
            'event_time'  => $entry['event_time']  ?? null,
            'event_type'  => $entry['event_type']  ?? null,
            'user_id'     => $entry['user_id']     ?? null,
            'target_type' => $entry['target_type'] ?? null,
            'target_id'   => $entry['target_id']   ?? null,
            'source_ip'   => $entry['source_ip']   ?? null,
            'user_agent'  => $entry['user_agent']  ?? null,
            'metadata'    => $entry['metadata']    ?? null,
        ];
        return json_encode($ordered, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}

if (!function_exists('securityAudit')) {

    /**
     * Append an entry to the security audit log.
     *
     * @param string $event_type      Short symbolic event name (e.g. 'login.password.success')
     * @param array  $details {
     *   @var int|null    $user_id
     *   @var string|null $target_type   Optional, e.g. 'credential', 'user'
     *   @var int|null    $target_id     Optional
     *   @var array|null  $metadata      Optional structured data (json_encode'd)
     *   @var string|null $source_ip     Defaults to $_SERVER['REMOTE_ADDR']
     *   @var string|null $user_agent    Defaults to $_SERVER['HTTP_USER_AGENT']
     * }
     * @return bool true if the entry was inserted
     */
    function securityAudit(string $event_type, array $details = []): bool
    {
        global $mysqli;

        if (!isset($mysqli) || !$mysqli) {
            return false;
        }

        // Wrap the entire body so the audit layer NEVER breaks the caller.
        // This degrades gracefully when the schema migration has not run yet
        // (table missing), or under transient DB issues. The audit log is
        // additive — its absence must not block authentication.
        try {
            $now_us     = microtime(true);
            $event_time = date('Y-m-d H:i:s', (int)$now_us) . sprintf('.%06d', ($now_us - (int)$now_us) * 1_000_000);

            $entry = [
                'event_time'  => $event_time,
                'event_type'  => $event_type,
                'user_id'     => isset($details['user_id']) ? intval($details['user_id']) : null,
                'target_type' => $details['target_type'] ?? null,
                'target_id'   => isset($details['target_id']) ? intval($details['target_id']) : null,
                'source_ip'   => $details['source_ip']   ?? ($_SERVER['REMOTE_ADDR'] ?? null),
                'user_agent'  => $details['user_agent']  ?? ($_SERVER['HTTP_USER_AGENT'] ?? null),
                'metadata'    => isset($details['metadata']) && is_array($details['metadata'])
                                    ? json_encode($details['metadata'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                                    : null,
            ];

            // Truncate user_agent and metadata to avoid blowing the schema.
            if ($entry['user_agent'] !== null) {
                $entry['user_agent'] = substr((string)$entry['user_agent'], 0, 500);
            }
            if ($entry['metadata'] !== null && strlen($entry['metadata']) > 65000) {
                $entry['metadata'] = substr($entry['metadata'], 0, 65000);
            }

            // Lock the table so the prev_hash we read remains the latest at the
            // moment of insert. Without this, two concurrent writers could read
            // the same prev_hash and produce a fork in the chain.
            mysqli_query($mysqli, 'LOCK TABLES security_audit_log WRITE');

            try {
                $row = mysqli_fetch_assoc(mysqli_query(
                    $mysqli,
                    "SELECT entry_hash FROM security_audit_log ORDER BY log_id DESC LIMIT 1"
                ));
                $prev_hash = $row ? $row['entry_hash'] : SECURITY_AUDIT_NULL_HASH;

                $canonical  = securityAuditCanonicalize($entry);
                $entry_hash = hash('sha256', $prev_hash . $canonical, true);

                $stmt = mysqli_prepare($mysqli,
                    "INSERT INTO security_audit_log
                     (event_time, event_type, user_id, target_type, target_id,
                      source_ip, user_agent, metadata, prev_hash, entry_hash)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                );
                if (!$stmt) {
                    return false;
                }

                $user_id   = $entry['user_id'];
                $target_id = $entry['target_id'];
                // Types: time, type, user_id, target_type, target_id, ip, ua, meta, prev, hash
                //        s     s     i        s            i          s   s   s     s     s
                mysqli_stmt_bind_param(
                    $stmt,
                    'ssisisssss',
                    $entry['event_time'],
                    $entry['event_type'],
                    $user_id,
                    $entry['target_type'],
                    $target_id,
                    $entry['source_ip'],
                    $entry['user_agent'],
                    $entry['metadata'],
                    $prev_hash,
                    $entry_hash
                );
                $ok = mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
                return (bool)$ok;
            } finally {
                @mysqli_query($mysqli, 'UNLOCK TABLES');
            }
        } catch (Throwable $e) {
            // Degrade silently. Log to PHP error log for diagnostics.
            error_log('securityAudit() suppressed error: ' . $e->getMessage());
            return false;
        }
    }
}

if (!function_exists('securityAuditLatestHash')) {

    function securityAuditLatestHash(mysqli $mysqli): ?string
    {
        $row = mysqli_fetch_assoc(mysqli_query(
            $mysqli,
            "SELECT entry_hash FROM security_audit_log ORDER BY log_id DESC LIMIT 1"
        ));
        if (!$row) return null;
        return bin2hex($row['entry_hash']);
    }
}
