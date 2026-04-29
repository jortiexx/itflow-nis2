#!/usr/bin/env php
<?php
/*
 * Phase 15: force-complete the legacy file encryption sweep (CLI).
 *
 * The opportunistic sweeper in includes/legacy_file_sweeper.php runs on
 * every authenticated agent session, ~25 files / 1 second per hour. For
 * smaller installs that's plenty. For installs with thousands of legacy
 * files, ops can run this script to push through the backlog in one go.
 *
 * Usage:
 *   php scripts/encrypt_legacy_files.php [--client-id=N] [--batch=100] [--dry-run]
 *
 * Requires: a vault session OR access to the shared master key. Without
 * those, the per-client master cannot be derived and the script exits
 * with a clear error. The simplest way to give it a vault session is to
 * run this script as a "logged-in user" — typically by booting a small
 * shim that re-creates the session ciphertext from a known passphrase.
 * Most installs will rely on the in-app sweeper instead.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/legacy_file_sweeper.php';

$batch_size  = 100;
$client_only = 0;
$dry_run     = false;

foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--dry-run') $dry_run = true;
    elseif (preg_match('/^--batch=(\d+)$/', $arg, $m)) $batch_size = intval($m[1]);
    elseif (preg_match('/^--client-id=(\d+)$/', $arg, $m)) $client_only = intval($m[1]);
}

if (!$mysqli || mysqli_connect_errno()) {
    fwrite(STDERR, "DB connection failed\n");
    exit(2);
}

echo "=== Legacy file encryption sweep (CLI) ===\n";
echo "Mode:        " . ($dry_run ? 'DRY-RUN' : 'LIVE') . "\n";
echo "Batch size:  $batch_size\n";
if ($client_only > 0) echo "Client only: $client_only\n";

if ($dry_run) {
    $where = "WHERE file_encrypted = 0 AND file_archived_at IS NULL";
    if ($client_only > 0) $where .= " AND file_client_id = $client_only";
    $r = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT COUNT(*) AS n, COUNT(DISTINCT file_client_id) AS clients FROM files $where"));
    echo "Plaintext rows: " . intval($r['n'] ?? 0) . " across " . intval($r['clients'] ?? 0) . " clients\n";
    exit(0);
}

// Walk all clients with remaining work.
$client_clause = $client_only > 0 ? "AND files.file_client_id = $client_only" : "";
$clients_sql =
   "SELECT DISTINCT files.file_client_id AS client_id
    FROM files
    LEFT JOIN client_master_keys cmk ON cmk.client_id = files.file_client_id
    WHERE files.file_encrypted = 0
      AND files.file_archived_at IS NULL
      AND (cmk.legacy_files_swept_at IS NULL OR cmk.client_id IS NULL)
      $client_clause
    ORDER BY files.file_client_id ASC";

$clients = [];
$res = mysqli_query($mysqli, $clients_sql);
while ($res && ($r = mysqli_fetch_assoc($res))) {
    $clients[] = intval($r['client_id']);
}
echo "Clients to process: " . count($clients) . "\n";

$total_encrypted = 0;
$total_failed    = 0;
$skipped         = [];

foreach ($clients as $cid) {
    echo "\n--- client_id=$cid ---\n";
    while (true) {
        $r = sweepLegacyFilesForClient($cid, $mysqli, $batch_size, 60.0);
        if (!empty($r['reason'])) {
            echo "  skipped: " . $r['reason'] . "\n";
            $skipped[] = ['client_id' => $cid, 'reason' => $r['reason']];
            break;
        }
        echo "  batch: encrypted={$r['encrypted']} failed={$r['failed']} remaining={$r['remaining']}\n";
        $total_encrypted += $r['encrypted'];
        $total_failed    += $r['failed'];
        if ($r['completed'] || ($r['encrypted'] === 0 && $r['failed'] === 0)) {
            if ($r['completed']) echo "  client complete.\n";
            else echo "  no more progress this round; stopping.\n";
            break;
        }
    }
}

echo "\n=== Summary ===\n";
echo "Total encrypted: $total_encrypted\n";
echo "Total failed:    $total_failed\n";
echo "Clients skipped: " . count($skipped) . "\n";
foreach ($skipped as $s) {
    echo "  client_id={$s['client_id']} reason={$s['reason']}\n";
}

exit($total_failed > 0 ? 1 : 0);
