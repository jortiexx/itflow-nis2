#!/usr/bin/env php
<?php
/*
 * Prune the security_audit_log table according to the configured retention.
 *
 * What it does:
 *  1. Reads `settings.config_security_audit_retention_days`
 *  2. Selects all entries with event_time older than that cutoff
 *  3. Writes them to a gzip-compressed JSONL archive in the configured
 *     archive directory (default: <itflow_root>/uploads/audit_archive/)
 *  4. Computes SHA-256 of the archive file
 *  5. Inserts a synthetic `audit.archived` event with metadata pointing to
 *     the archive (filename, sha256, count, first/last log_id, last entry_hash)
 *  6. Re-anchors the live chain by writing this event with prev_hash=NULL_HASH
 *     and a recomputed entry_hash. The verifier walks the live chain from
 *     this row onward; the archive is the forensic record for older entries.
 *  7. Deletes the archived rows
 *
 * Designed for a daily cron:
 *   0 3 * * *  /usr/bin/php /path/to/itflow/scripts/audit_prune.php
 *
 * Output is line-oriented and friendly to log aggregation. Exit code is
 * non-zero on any failure (writes to stderr).
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once 'config.php';
require_once 'functions.php';
require_once 'includes/security_audit.php';

// ---- read retention config -------------------------------------------------
$row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT config_security_audit_retention_days FROM settings WHERE company_id = 1 LIMIT 1"
));
$retention_days = $row ? intval($row['config_security_audit_retention_days']) : 0;

if ($retention_days <= 0) {
    echo "audit_prune: retention disabled (config_security_audit_retention_days=$retention_days). Nothing to do.\n";
    exit(0);
}

$cutoff = date('Y-m-d H:i:s', strtotime("-$retention_days days"));
echo "audit_prune: retention=$retention_days days, cutoff=$cutoff\n";

// ---- select rows to archive -----------------------------------------------
$rs = mysqli_query(
    $mysqli,
    "SELECT log_id, event_time, event_type, user_id, target_type, target_id,
            source_ip, user_agent, metadata, prev_hash, entry_hash
     FROM security_audit_log
     WHERE event_time < '$cutoff'
     ORDER BY log_id ASC"
);
if (!$rs) {
    fwrite(STDERR, "audit_prune: SELECT failed: " . mysqli_error($mysqli) . "\n");
    exit(1);
}
$count = mysqli_num_rows($rs);
if ($count === 0) {
    echo "audit_prune: no entries older than cutoff. Nothing to do.\n";
    exit(0);
}

// ---- write archive --------------------------------------------------------
$archive_dir = __DIR__ . '/../uploads/audit_archive';
if (!is_dir($archive_dir)) {
    if (!@mkdir($archive_dir, 0700, true)) {
        fwrite(STDERR, "audit_prune: could not create archive dir $archive_dir\n");
        exit(1);
    }
}

$stamp        = date('Y-m-d_His');
$archive_name = "audit_$stamp.jsonl.gz";
$archive_path = "$archive_dir/$archive_name";

$gz = gzopen($archive_path, 'w9');
if (!$gz) {
    fwrite(STDERR, "audit_prune: could not open $archive_path for writing\n");
    exit(1);
}

$first_log_id   = null;
$last_log_id    = null;
$last_entry_hash = null;
while ($row = mysqli_fetch_assoc($rs)) {
    if ($first_log_id === null) $first_log_id = intval($row['log_id']);
    $last_log_id     = intval($row['log_id']);
    $last_entry_hash = $row['entry_hash'];

    // Hex-encode the binary fields so the JSONL is plain ASCII and
    // re-importable without binary handling.
    $row['prev_hash']  = bin2hex($row['prev_hash']);
    $row['entry_hash'] = bin2hex($row['entry_hash']);
    gzwrite($gz, json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}
gzclose($gz);

$archive_sha = hash_file('sha256', $archive_path);

echo "audit_prune: archived $count rows (log_id $first_log_id..$last_log_id) to $archive_path\n";
echo "audit_prune: archive sha256 = $archive_sha\n";

// ---- insert re-anchor marker ----------------------------------------------
$now_us = microtime(true);
$event_time = date('Y-m-d H:i:s', (int)$now_us) . sprintf('.%06d', ($now_us - (int)$now_us) * 1_000_000);

$marker = [
    'event_time'  => $event_time,
    'event_type'  => 'audit.archived',
    'user_id'     => null,
    'target_type' => null,
    'target_id'   => null,
    'source_ip'   => null,
    'user_agent'  => null,
    'metadata'    => json_encode([
        'archived_count'       => $count,
        'first_log_id'         => $first_log_id,
        'last_log_id'          => $last_log_id,
        'last_entry_hash_hex'  => bin2hex($last_entry_hash),
        'archive_filename'     => $archive_name,
        'archive_sha256'       => $archive_sha,
        'retention_days_at_run'=> $retention_days,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
];

$canonical  = securityAuditCanonicalize($marker);
$prev_hash  = SECURITY_AUDIT_NULL_HASH;            // re-anchor
$entry_hash = hash('sha256', $prev_hash . $canonical, true);

mysqli_query($mysqli, 'LOCK TABLES security_audit_log WRITE');
try {
    $stmt = mysqli_prepare($mysqli,
        "INSERT INTO security_audit_log
         (event_time, event_type, user_id, target_type, target_id,
          source_ip, user_agent, metadata, prev_hash, entry_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    $u = $marker['user_id'];
    $t = $marker['target_id'];
    mysqli_stmt_bind_param(
        $stmt,
        'ssisisssss',
        $marker['event_time'], $marker['event_type'],
        $u,
        $marker['target_type'], $t,
        $marker['source_ip'], $marker['user_agent'], $marker['metadata'],
        $prev_hash, $entry_hash
    );
    if (!mysqli_stmt_execute($stmt)) {
        fwrite(STDERR, "audit_prune: marker INSERT failed: " . mysqli_stmt_error($stmt) . "\n");
        @mysqli_query($mysqli, 'UNLOCK TABLES');
        exit(1);
    }
    mysqli_stmt_close($stmt);

    $delete_ok = mysqli_query(
        $mysqli,
        "DELETE FROM security_audit_log WHERE log_id <= $last_log_id"
    );
    if (!$delete_ok) {
        fwrite(STDERR, "audit_prune: DELETE failed: " . mysqli_error($mysqli) . "\n");
        @mysqli_query($mysqli, 'UNLOCK TABLES');
        exit(1);
    }
} finally {
    mysqli_query($mysqli, 'UNLOCK TABLES');
}

echo "audit_prune: deleted $count archived rows; chain re-anchored at the new audit.archived marker\n";
echo "audit_prune: latest entry_hash = " . bin2hex($entry_hash) . "\n";
exit(0);
