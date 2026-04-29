#!/usr/bin/env php
<?php
/*
 * Walk the security_audit_log hash chain end-to-end and report any
 * inconsistencies. Exits 0 on a clean walk, 1 on any tampering signal.
 *
 * Usage:
 *   php scripts/audit_verify.php [--from=ID] [--to=ID]
 *
 * Options:
 *   --from=ID  Start from a specific log_id (uses prev_hash from row before)
 *   --to=ID    Stop at a specific log_id (inclusive)
 *
 * Use cases:
 *   - Regular cron job: alert on any failure (exit code != 0)
 *   - Forensic investigation: pin a known-good entry_hash externally
 *     (paper, SIEM cold storage), then re-verify against it.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "This script must be run from the CLI.\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_audit.php';

$opts = getopt('', ['from::', 'to::', 'all', 'help']);
if (isset($opts['help'])) {
    echo "Usage: php scripts/audit_verify.php [--from=ID] [--to=ID] [--all]\n";
    echo "  --from=ID  Start from a specific log_id (uses prev_hash from row before).\n";
    echo "  --to=ID    Stop at a specific log_id (inclusive).\n";
    echo "  --all      Walk from log_id=1 even when an audit.archived re-anchor\n";
    echo "             marker exists. Without this flag, verification starts at\n";
    echo "             the latest archived marker because pre-marker entries are\n";
    echo "             expected to have stale prev_hash values pointing into\n";
    echo "             pruned (deleted) rows.\n";
    exit(0);
}

$from = isset($opts['from']) ? intval($opts['from']) : 0;
$to   = isset($opts['to'])   ? intval($opts['to'])   : PHP_INT_MAX;
$walk_all = isset($opts['all']);

// If no explicit --from and no --all, auto-anchor at the latest
// audit.archived marker so the chain after pruning verifies cleanly.
if ($from === 0 && !$walk_all) {
    $marker_row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT log_id FROM security_audit_log
         WHERE event_type = 'audit.archived'
         ORDER BY log_id DESC LIMIT 1"
    ));
    if ($marker_row) {
        $from = intval($marker_row['log_id']);
        echo "audit_verify: auto-anchoring at log_id=$from (latest audit.archived marker; pass --all to walk earlier rows)\n";
    }
}

// Determine starting prev_hash.
//   - If --from points at an audit.archived marker, the marker is itself a
//     re-anchor (prev_hash = NULL_HASH by construction), so start from genesis.
//   - If --from is some other row, take the entry_hash of the row before.
//   - Otherwise start from the null hash (genesis).
if ($from > 1) {
    $start_row = mysqli_fetch_assoc(mysqli_query(
        $mysqli,
        "SELECT event_type FROM security_audit_log WHERE log_id = $from LIMIT 1"
    ));
    if ($start_row && $start_row['event_type'] === 'audit.archived') {
        $prev_hash = SECURITY_AUDIT_NULL_HASH;
    } else {
        $row = mysqli_fetch_assoc(mysqli_query(
            $mysqli,
            "SELECT entry_hash FROM security_audit_log WHERE log_id = " . ($from - 1) . " LIMIT 1"
        ));
        if (!$row) {
            fwrite(STDERR, "Row before --from=$from not found.\n");
            exit(1);
        }
        $prev_hash = $row['entry_hash'];
    }
} else {
    $prev_hash = SECURITY_AUDIT_NULL_HASH;
}

$walked     = 0;
$failures   = 0;
$last_id    = 0;
$first_bad  = null;
$last_known = null;

$rs = mysqli_query(
    $mysqli,
    "SELECT log_id, event_time, event_type, user_id, target_type, target_id,
            source_ip, user_agent, metadata, prev_hash, entry_hash
     FROM security_audit_log
     WHERE log_id BETWEEN $from AND $to
     ORDER BY log_id ASC"
);

if (!$rs) {
    fwrite(STDERR, "Query failed: " . mysqli_error($mysqli) . "\n");
    exit(1);
}

while ($row = mysqli_fetch_assoc($rs)) {
    $walked++;
    $last_id = intval($row['log_id']);

    // Check stored prev_hash matches our running prev_hash.
    if (!hash_equals($prev_hash, $row['prev_hash'])) {
        $failures++;
        if ($first_bad === null) $first_bad = $last_id;
        echo "[BREAK]  log_id={$row['log_id']}: prev_hash mismatch (chain broken)\n";
    }

    // Recompute entry_hash from canonical entry + stored prev_hash.
    $canonical = securityAuditCanonicalize($row);
    $expected  = hash('sha256', $row['prev_hash'] . $canonical, true);
    if (!hash_equals($expected, $row['entry_hash'])) {
        $failures++;
        if ($first_bad === null) $first_bad = $last_id;
        echo "[FORGE]  log_id={$row['log_id']}: entry_hash does not match recomputed value\n";
    }

    // Advance: even on failure, follow the stored chain so we don't cascade
    // false positives downstream (we want one report per actual break).
    $prev_hash = $row['entry_hash'];
    $last_known = $row;
}

if ($walked === 0) {
    echo "No entries in range. Nothing to verify.\n";
    exit(0);
}

if ($failures === 0) {
    echo "OK: $walked entries verified, no inconsistencies.\n";
    if ($last_known) {
        echo "Last entry: log_id={$last_known['log_id']} time={$last_known['event_time']} type={$last_known['event_type']}\n";
        echo "Last entry_hash: " . bin2hex($last_known['entry_hash']) . "\n";
    }
    exit(0);
}

echo "\nFAIL: $failures inconsistencies across $walked entries (first at log_id $first_bad)\n";
exit(1);
