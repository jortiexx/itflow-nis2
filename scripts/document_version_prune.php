#!/usr/bin/env php
<?php
/*
 * Document version retention pruning (phase 13 / E).
 *
 * Deletes rows from `document_versions` whose document_version_created_at is
 * older than `settings.config_document_version_retention_days` days. The
 * canonical (latest) document body in `documents` is never touched — only
 * historical versions are pruned.
 *
 * Run from cron (e.g. nightly):
 *   php /path/to/itflow/scripts/document_version_prune.php
 *
 * Flags:
 *   --dry-run   Report what would be deleted, don't delete.
 *   --verbose   Print per-row info.
 *
 * Always emits an audit record (audit.document_version_prune) summarising
 * the run, even on dry-run.
 */

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "CLI only\n");
    exit(1);
}

chdir(__DIR__ . '/..');
require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_audit.php';

$dry_run = in_array('--dry-run', $argv, true);
$verbose = in_array('--verbose', $argv, true);

if (!$mysqli || mysqli_connect_errno()) {
    fwrite(STDERR, "DB connection failed: " . mysqli_connect_error() . "\n");
    exit(2);
}

// Read retention from settings. Default to 365 days if column missing.
$retention_days = 365;
$row = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_document_version_retention_days FROM settings LIMIT 1"));
if ($row && intval($row['config_document_version_retention_days']) > 0) {
    $retention_days = intval($row['config_document_version_retention_days']);
}

if ($retention_days <= 0) {
    echo "Retention disabled (config_document_version_retention_days = $retention_days). Exiting.\n";
    exit(0);
}

// Find candidates older than the cutoff.
$cutoff_sql = sprintf(
    "SELECT document_version_id, document_version_document_id, document_version_name,
            document_version_created_at
     FROM document_versions
     WHERE document_version_created_at < (NOW() - INTERVAL %d DAY)
     ORDER BY document_version_id ASC",
    $retention_days
);

$res = mysqli_query($mysqli, $cutoff_sql);
if (!$res) {
    fwrite(STDERR, "Query failed: " . mysqli_error($mysqli) . "\n");
    exit(3);
}

$candidates = [];
while ($r = mysqli_fetch_assoc($res)) {
    $candidates[] = $r;
}
$count = count($candidates);

echo "=== Document version pruning ===\n";
echo "Retention:    $retention_days days\n";
echo "Mode:         " . ($dry_run ? 'DRY-RUN (no deletes)' : 'LIVE') . "\n";
echo "Candidates:   $count rows\n";

if ($count === 0) {
    securityAudit('document_version.prune', [
        'metadata' => [
            'retention_days' => $retention_days,
            'deleted'        => 0,
            'dry_run'        => $dry_run,
        ],
    ]);
    echo "Nothing to do.\n";
    exit(0);
}

$deleted = 0;
foreach ($candidates as $c) {
    $vid = intval($c['document_version_id']);
    $did = intval($c['document_version_document_id']);
    $name = $c['document_version_name'];
    $created = $c['document_version_created_at'];
    if ($verbose) {
        echo "  - version_id=$vid document_id=$did created=$created name=$name\n";
    }
    if (!$dry_run) {
        $ok = mysqli_query($mysqli,
            "DELETE FROM document_versions WHERE document_version_id = $vid");
        if ($ok) {
            $deleted++;
        } else {
            fwrite(STDERR, "  [WARN] could not delete version_id=$vid: "
                . mysqli_error($mysqli) . "\n");
        }
    }
}

if ($dry_run) {
    echo "Would delete: $count\n";
} else {
    echo "Deleted:      $deleted / $count\n";
}

securityAudit('document_version.prune', [
    'metadata' => [
        'retention_days' => $retention_days,
        'candidates'     => $count,
        'deleted'        => $dry_run ? 0 : $deleted,
        'dry_run'        => $dry_run,
    ],
]);

exit(0);
