<?php
/*
 * PHP-mediated file download endpoint.
 *
 * Replaces direct linking to /uploads/clients/X/Y. Every file fetch goes
 * through this endpoint which:
 *   1. Authenticates the user (check_login)
 *   2. Verifies the user has app-layer access to the file's client
 *   3. Decrypts the file if it was stored encrypted (phase 13)
 *   4. Audits the access in security_audit_log
 *   5. Streams the bytes with appropriate Content-Disposition
 *
 * Usage:
 *   /agent/file_download.php?id=123              → attachment download
 *   /agent/file_download.php?id=123&inline=1     → inline (for <img>)
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../functions.php';
require_once __DIR__ . '/../includes/security_headers.php';
require_once __DIR__ . '/../includes/check_login.php';
require_once __DIR__ . '/../includes/file_storage.php';
require_once __DIR__ . '/../includes/security_audit.php';

$file_id = intval($_GET['id'] ?? 0);
$inline  = isset($_GET['inline']) && $_GET['inline'] == '1';
if ($file_id <= 0) {
    http_response_code(400);
    exit('Missing file id.');
}

$row = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT file_id, file_reference_name, file_name, file_ext, file_mime_type,
            file_mime_verified, file_size, file_client_id,
            file_encrypted, file_encryption_iv, file_encryption_tag,
            file_sha256, file_archived_at
     FROM files
     WHERE file_id = $file_id LIMIT 1"));
if (!$row) {
    http_response_code(404);
    exit('File not found.');
}

if (!empty($row['file_archived_at'])) {
    http_response_code(410);
    exit('File archived.');
}

$client_id = intval($row['file_client_id']);

// App-layer access check: admin OR explicit user_client_permissions match.
// Mirrors the global $access_permission_query logic that other pages use.
if (!$session_is_admin) {
    $allowed = false;
    if ($client_id > 0) {
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT COUNT(*) AS n FROM user_client_permissions
             WHERE user_id = $session_user_id AND client_id = $client_id"));
        if ($r && intval($r['n']) > 0) {
            $allowed = true;
        }
        // If user has no explicit permission rows at all, they have access
        // to everything (ITFlow's default unrestricted model).
        $r2 = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT COUNT(*) AS n FROM user_client_permissions WHERE user_id = $session_user_id"));
        if ($r2 && intval($r2['n']) === 0) {
            $allowed = true;
        }
    }
    if (!$allowed) {
        http_response_code(403);
        securityAudit('file.download.denied', [
            'user_id'     => $session_user_id,
            'target_type' => 'file',
            'target_id'   => $file_id,
            'metadata'    => ['client_id' => $client_id, 'reason' => 'no_grant'],
        ]);
        exit('Forbidden.');
    }
}

$disk_path = __DIR__ . "/../uploads/clients/$client_id/" . $row['file_reference_name'];
if (!is_file($disk_path) || !is_readable($disk_path)) {
    http_response_code(404);
    exit('File missing on disk.');
}

$bytes = file_get_contents($disk_path);
if ($bytes === false) {
    http_response_code(500);
    exit('Cannot read file from disk.');
}

// Decrypt if stored encrypted (phase 13). Files uploaded before phase 13
// are stored as plaintext on disk and have file_encrypted = 0.
if (!empty($row['file_encrypted'])) {
    $iv  = $row['file_encryption_iv'];
    $tag = $row['file_encryption_tag'];
    if (!is_string($iv) || !is_string($tag) || strlen($iv) !== 12 || strlen($tag) !== 16) {
        http_response_code(500);
        exit('Encrypted file metadata is invalid.');
    }
    $plaintext = decryptFileAtRest($bytes, $iv, $tag, $client_id, $mysqli);
    if ($plaintext === null) {
        http_response_code(500);
        securityAudit('file.download.decrypt_failed', [
            'user_id'     => $session_user_id,
            'target_type' => 'file',
            'target_id'   => $file_id,
            'metadata'    => ['client_id' => $client_id],
        ]);
        exit('Could not decrypt file. Vault locked or grant missing.');
    }
    $bytes = $plaintext;
}

// Optional integrity check: if file_sha256 is set, verify it now.
if (!empty($row['file_sha256'])) {
    $actual = hash('sha256', $bytes, true);
    if (!hash_equals($actual, $row['file_sha256'])) {
        securityAudit('file.integrity.failed', [
            'user_id'     => $session_user_id,
            'target_type' => 'file',
            'target_id'   => $file_id,
            'metadata'    => [
                'expected_sha256' => bin2hex($row['file_sha256']),
                'actual_sha256'   => bin2hex($actual),
            ],
        ]);
        http_response_code(500);
        exit('File integrity check failed. Refusing to serve a tampered file.');
    }
}

securityAudit('file.download', [
    'user_id'     => $session_user_id,
    'target_type' => 'file',
    'target_id'   => $file_id,
    'metadata'    => [
        'client_id' => $client_id,
        'name'      => $row['file_name'],
        'size'      => intval($row['file_size']),
        'inline'    => $inline,
    ],
]);

$mime = $row['file_mime_verified'] ?: ($row['file_mime_type'] ?: 'application/octet-stream');
$disposition = $inline ? 'inline' : 'attachment';
$ascii_name = preg_replace('/[\x00-\x1f"\\\\]/', '_', (string)$row['file_name']);

header('Content-Type: ' . $mime);
header('Content-Length: ' . strlen($bytes));
header('Content-Disposition: ' . $disposition . '; filename="' . $ascii_name . '"');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: private, no-store');
echo $bytes;
exit;
