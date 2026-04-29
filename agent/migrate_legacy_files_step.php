<?php
/*
 * Phase 15: AJAX worker for the legacy-file migration UI.
 *
 * Each call: process up to 100 plaintext files (3 second time budget),
 * return JSON with batch result + total remaining for this user.
 *
 * Called from /agent/migrate_legacy_files.php in a polling loop.
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/check_login.php';
require_once __DIR__ . '/../includes/legacy_file_sweeper.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

// Inline CSRF check — validateCSRFToken() redirects on failure which
// would break the JSON contract. Mirror its hash_equals logic here so we
// can return a clean 403 with a JSON body.
if (!isset($_POST['csrf_token'])
    || !is_string($_SESSION['csrf_token'] ?? null)
    || !hash_equals($_SESSION['csrf_token'], (string)$_POST['csrf_token'])) {
    http_response_code(403);
    echo json_encode(['error' => 'invalid_csrf']);
    exit;
}

// Process one batch. The sweep helper stays under the time budget by
// checking microtime() between files; LIMIT in the SQL keeps the work
// set bounded.
$result = sweepLegacyFilesOpportunistic($mysqli, $session_user_id, $session_is_admin, 3.0);

// Recompute total remaining for this user — that drives the progress bar.
$remaining = legacyFilesPendingForUser($mysqli, $session_user_id, $session_is_admin);

echo json_encode([
    'encrypted_this_batch' => intval($result['encrypted'] ?? 0),
    'failed_this_batch'    => intval($result['failed'] ?? 0),
    'remaining'            => $remaining,
    'reason'               => $result['reason'] ?? null,
]);
exit;
