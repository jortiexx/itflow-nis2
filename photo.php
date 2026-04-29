<?php
/*
 * PHP-mediated photo endpoint.
 *
 * Replaces direct linking to /uploads/clients/<X>/<photo>.jpg and
 * /uploads/users/<X>/<avatar>.jpg. Every photo fetch goes through this
 * endpoint, which:
 *   1. Authenticates the viewer (agent session OR client portal session)
 *   2. Looks up the canonical filename from the parent table
 *   3. Verifies the viewer is allowed to see that client's data
 *   4. Confirms the bytes are actually an image (server-side finfo)
 *   5. Audits denials in security_audit_log
 *   6. Streams the bytes
 *
 * Usage:
 *   /photo.php?type=contact&id=42
 *   /photo.php?type=asset&id=123
 *   /photo.php?type=rack&id=7
 *   /photo.php?type=location&id=3
 *   /photo.php?type=user&id=5      (operator avatar; any authenticated session)
 *
 * Successful photo fetches are NOT individually audited — every list page
 * renders dozens of thumbnails, so we'd flood the audit log. Denied
 * accesses ARE audited (photo.access.denied).
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/includes/session_init.php';
require_once __DIR__ . '/includes/security_audit.php';

$type = $_GET['type'] ?? '';
$id   = intval($_GET['id'] ?? 0);

$valid_types = ['contact', 'asset', 'rack', 'location', 'user'];
if ($id <= 0 || !in_array($type, $valid_types, true)) {
    http_response_code(400);
    exit('Bad request.');
}

// Detect viewer kind.
$is_agent  = !empty($_SESSION['logged']);
$is_client = !empty($_SESSION['client_logged_in']);
if (!$is_agent && !$is_client) {
    http_response_code(401);
    exit('Auth required.');
}

$viewer_user_id   = 0;
$viewer_is_admin  = false;
$viewer_client_id = 0;

if ($is_agent) {
    // Minimal inline session resolution — full load_user_session.php would
    // pull half the global app state and is overkill for a photo fetch.
    $viewer_user_id = intval($_SESSION['user_id'] ?? 0);
    if ($viewer_user_id <= 0) {
        http_response_code(401);
        exit('Auth required.');
    }
    $r = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT user_roles.role_is_admin, users.user_status, users.user_archived_at, users.user_type
         FROM users
         LEFT JOIN user_settings ON users.user_id = user_settings.user_id
         LEFT JOIN user_roles ON user_settings.user_role_id = user_roles.role_id
         WHERE users.user_id = $viewer_user_id LIMIT 1"));
    if (!$r || intval($r['user_status']) !== 1 || $r['user_archived_at'] !== null || intval($r['user_type']) !== 1) {
        http_response_code(401);
        exit('Auth required.');
    }
    $viewer_is_admin = intval($r['role_is_admin'] ?? 0) === 1;
} else {
    $viewer_client_id = intval($_SESSION['client_id'] ?? 0);
    if ($viewer_client_id <= 0) {
        http_response_code(401);
        exit('Auth required.');
    }
}

// Resolve the photo's parent record + on-disk path.
$filename  = null;
$client_id = 0;
$base_dir  = null;

switch ($type) {
    case 'contact':
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT contact_photo, contact_client_id FROM contacts WHERE contact_id = $id LIMIT 1"));
        if ($r) {
            $filename  = $r['contact_photo'];
            $client_id = intval($r['contact_client_id']);
        }
        $base_dir = __DIR__ . "/uploads/clients/$client_id";
        break;

    case 'asset':
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT asset_photo, asset_client_id FROM assets WHERE asset_id = $id LIMIT 1"));
        if ($r) {
            $filename  = $r['asset_photo'];
            $client_id = intval($r['asset_client_id']);
        }
        $base_dir = __DIR__ . "/uploads/clients/$client_id";
        break;

    case 'rack':
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT rack_photo, rack_client_id FROM racks WHERE rack_id = $id LIMIT 1"));
        if ($r) {
            $filename  = $r['rack_photo'];
            $client_id = intval($r['rack_client_id']);
        }
        $base_dir = __DIR__ . "/uploads/clients/$client_id";
        break;

    case 'location':
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT location_photo, location_client_id FROM locations WHERE location_id = $id LIMIT 1"));
        if ($r) {
            $filename  = $r['location_photo'];
            $client_id = intval($r['location_client_id']);
        }
        $base_dir = __DIR__ . "/uploads/clients/$client_id";
        break;

    case 'user':
        $r = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT user_avatar FROM users WHERE user_id = $id LIMIT 1"));
        if ($r) {
            $filename = $r['user_avatar'];
        }
        $base_dir = __DIR__ . "/uploads/users/$id";
        break;
}

if (!$filename) {
    http_response_code(404);
    exit('No photo.');
}

// ACL.
$allowed = false;
if ($type === 'user') {
    // Operator avatars are work-context photos of MSP staff and are
    // referenced from ticket reply panels in both the agent UI and the
    // client portal. Any authenticated session may fetch them.
    $allowed = true;
} elseif ($is_agent) {
    if ($viewer_is_admin) {
        $allowed = true;
    } else {
        // Same model as agent/file_download.php: explicit grant OR
        // user has no rows in user_client_permissions at all (the
        // unrestricted-default-fallback).
        $u = $viewer_user_id;
        $r1 = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT COUNT(*) AS n FROM user_client_permissions
             WHERE user_id = $u AND client_id = $client_id"));
        $r2 = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT COUNT(*) AS n FROM user_client_permissions
             WHERE user_id = $u"));
        $allowed = (intval($r1['n'] ?? 0) > 0)
                || (intval($r2['n'] ?? 0) === 0);
    }
} elseif ($is_client) {
    // Client portal viewer may only see photos under their own client.
    $allowed = ($viewer_client_id === $client_id);
}

if (!$allowed) {
    http_response_code(403);
    securityAudit('photo.access.denied', [
        'user_id'     => $viewer_user_id,
        'target_type' => 'photo',
        'target_id'   => $id,
        'metadata'    => [
            'type'      => $type,
            'client_id' => $client_id,
            'viewer'    => $is_agent ? 'agent' : 'client',
        ],
    ]);
    exit('Forbidden.');
}

// On-disk path. basename() neutralises any path-traversal smuggled through
// the DB column (defence in depth — the column is normally a 16+ char
// random reference name).
$disk_path = $base_dir . '/' . basename($filename);
if (!is_file($disk_path) || !is_readable($disk_path)) {
    http_response_code(404);
    exit('File missing on disk.');
}

// Server-side MIME check. This endpoint is *only* for images — refuse to
// serve anything else even if the column happens to point at a non-image
// (e.g. a renamed PDF that slipped past validation).
$mime = 'application/octet-stream';
if (function_exists('finfo_open')) {
    $f = finfo_open(FILEINFO_MIME_TYPE);
    if ($f) {
        $detected = finfo_file($f, $disk_path);
        if ($detected) $mime = $detected;
        finfo_close($f);
    }
}
if (!preg_match('#^image/(jpeg|png|gif|webp|svg\+xml|x-icon|vnd\.microsoft\.icon)$#', $mime)) {
    http_response_code(415);
    exit('Not an image.');
}

header('Content-Type: ' . $mime);
header('Content-Length: ' . filesize($disk_path));
header('X-Content-Type-Options: nosniff');
// Photos rarely change. Allow private (per-session) caching for an hour
// so list pages with dozens of thumbnails stay snappy.
header('Cache-Control: private, max-age=3600');
readfile($disk_path);
exit;
