<?php
/*
 * Tactical RMM -> ITFlow sync (replaces the n8n "TRMM -> ITflow" workflow).
 *
 * - Every TRMM client is linked to an ITFlow client through trmm_client_map,
 *   keyed on the TRMM client ID. A TRMM client seen for the first time is
 *   linked to the ITFlow client with exactly the same name, or a new ITFlow
 *   client (with primary legal entity) is created. After that, renaming on
 *   either side has no effect. Set trmm_skip = 1 to ignore a TRMM client.
 * - Every agent becomes an asset. Assets are matched on their TRMM URL
 *   (asset_uri = <web url>/agents/<agent_id>), so two machines with the same
 *   hostname stay two assets, and an asset moved to another client in ITFlow
 *   stays where it is. ITFlow owns the asset after creation; the sync only
 *   keeps description, OS and primary IP current. Archived assets are left
 *   alone and never recreated.
 * - New assets get the BIOS release date as purchase date and the Windows
 *   install date as install date (both from TRMM's WMI data), when known.
 *
 * Crontab: *\/10 * * * * sudo -u www-data php /var/www/<site>/cron/trmm_sync.php
 * Usage:   php trmm_sync.php [--dry-run] [--verbose]
 *
 * Reads:  settings.config_trmm_api_url, config_trmm_api_key, config_trmm_web_url
 * Writes: trmm_client_map, clients, client_entities, assets, asset_interfaces,
 *         asset_history, logs, settings.config_trmm_last_sync_at
 */

chdir(dirname(__FILE__));
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

require_once "../config.php";
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

$dry_run = in_array('--dry-run', $argv, true);
$verbose = in_array('--verbose', $argv, true) || $dry_run;

// logAction() reads these globals
$session_ip = '127.0.0.1';
$session_user_agent = 'trmm-sync';
$session_user_id = 0;

function trmm_log($msg) { fwrite(STDOUT, '[' . date('Y-m-d H:i:s') . '] ' . $msg . "\n"); }
function trmm_err($msg) { fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $msg . "\n"); }

// One run at a time
$lock = fopen(sys_get_temp_dir() . '/itflow_trmm_sync.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    trmm_log('Previous run still active, exiting.');
    exit(0);
}

$cfg = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_trmm_api_url, config_trmm_api_key, config_trmm_web_url, config_default_net_terms
     FROM settings WHERE company_id = 1 LIMIT 1"));
$api_url = rtrim($cfg['config_trmm_api_url'] ?? '', '/');
$api_key = $cfg['config_trmm_api_key'] ?? '';
$web_url = rtrim($cfg['config_trmm_web_url'] ?? '', '/');
$net_terms = intval($cfg['config_default_net_terms'] ?? 30);
if (!$api_url || !$api_key || !$web_url) {
    trmm_err('TRMM API URL, key or web URL not configured (settings.config_trmm_*).');
    exit(2);
}
$currency = mysqli_fetch_row(mysqli_query($mysqli, "SELECT company_currency FROM companies WHERE company_id = 1"))[0] ?? 'EUR';

function trmm_get(string $api_url, string $api_key, string $path) {
    $ch = curl_init($api_url . $path);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ['X-API-KEY: ' . $api_key, 'Accept: application/json'],
        CURLOPT_TIMEOUT        => 120,
        CURLOPT_CONNECTTIMEOUT => 10,
    ]);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($raw === false || $code !== 200) {
        throw new RuntimeException("GET $path failed: HTTP $code $err");
    }
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        throw new RuntimeException("GET $path returned invalid JSON");
    }
    return $data;
}

function esc($s) {
    global $mysqli;
    return mysqli_real_escape_string($mysqli, (string)$s);
}

// First usable LAN IPv4 from TRMM's comma separated local_ips, same rules as the n8n workflow
function pick_ip(?string $local_ips): string {
    foreach (explode(',', (string)$local_ips) as $ip) {
        $ip = trim($ip);
        if ($ip === '' || strpos($ip, 'error') !== false || strpos($ip, ':') !== false
            || strpos($ip, '10.147.') === 0 || strpos($ip, '169.254.') === 0) {
            continue;
        }
        return explode('/', $ip)[0];
    }
    return '';
}

function asset_type(array $a): string {
    if (($a['monitoring_type'] ?? '') === 'server') {
        return stripos($a['make_model'] ?? '', 'QEMU') !== false ? 'Virtual Machine' : 'Server';
    }
    return 'Desktop';
}

// BIOS release date and Windows install date from the agent's WMI detail
function agent_dates(string $api_url, string $api_key, string $agent_id): array {
    try {
        $d = trmm_get($api_url, $api_key, '/agents/' . rawurlencode($agent_id) . '/');
    } catch (RuntimeException $e) {
        return [null, null];
    }
    $first = function ($k) use ($d) {
        $v = $d['wmi_detail'][$k] ?? [];
        while (is_array($v) && isset($v[0])) {
            $v = $v[0];
        }
        return is_array($v) ? $v : [];
    };
    $date = function ($s) {
        $s = substr((string)$s, 0, 10);
        return (preg_match('/^\d{4}-\d{2}-\d{2}$/', $s) && $s > '1990-01-01') ? $s : null;
    };
    return [$date($first('bios')['ReleaseDate'] ?? ''), $date($first('os')['InstallDate'] ?? '')];
}

try {
    $trmm_clients = trmm_get($api_url, $api_key, '/clients/');
    $agents = trmm_get($api_url, $api_key, '/agents/');
} catch (RuntimeException $e) {
    trmm_err($e->getMessage());
    exit(1);
}

$stats = ['clients_linked' => 0, 'clients_created' => 0, 'assets_created' => 0, 'assets_updated' => 0, 'agents_skipped' => 0];
$changes = [];

// ---- Clients ---------------------------------------------------------------

$map = [];
$res = mysqli_query($mysqli, "SELECT trmm_client_id, client_id, trmm_skip FROM trmm_client_map");
while ($r = mysqli_fetch_assoc($res)) {
    $map[intval($r['trmm_client_id'])] = $r;
}
$name_to_trmm_id = [];

foreach ($trmm_clients as $tc) {
    $tid = intval($tc['id']);
    $tname = trim($tc['name']);
    $name_to_trmm_id[$tname] = $tid;

    if (isset($map[$tid])) {
        continue;
    }

    $itflow = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT client_id FROM clients WHERE client_name = '" . esc($tname) . "' AND client_archived_at IS NULL ORDER BY client_id LIMIT 1"));

    if ($itflow) {
        $cid = intval($itflow['client_id']);
        $changes[] = "link TRMM client '$tname' ($tid) to ITFlow client $cid";
        $stats['clients_linked']++;
    } else {
        $changes[] = "create ITFlow client '$tname' for TRMM client $tid";
        $stats['clients_created']++;
        $cid = null;
        if (!$dry_run) {
            $n = esc($tname);
            mysqli_query($mysqli, "INSERT INTO clients SET client_name = '$n', client_currency_code = '" . esc($currency) . "', client_net_terms = $net_terms, client_accessed_at = NOW()");
            $cid = mysqli_insert_id($mysqli);
            mysqli_query($mysqli, "INSERT INTO client_entities SET entity_client_id = $cid, entity_name = '$n', entity_primary = 1");
            logAction("Client", "Create", esc("$tname via TRMM sync"), $cid, $cid);
        }
    }

    if (!$dry_run) {
        mysqli_query($mysqli, "INSERT INTO trmm_client_map SET trmm_client_id = $tid, trmm_client_name = '" . esc($tname) . "', client_id = " . intval($cid));
    }
    $map[$tid] = ['trmm_client_id' => $tid, 'client_id' => $cid ?? -1, 'trmm_skip' => 0];
}

// Keep the TRMM name in the map current (informational only)
if (!$dry_run) {
    foreach ($name_to_trmm_id as $tname => $tid) {
        mysqli_query($mysqli, "UPDATE trmm_client_map SET trmm_client_name = '" . esc($tname) . "' WHERE trmm_client_id = $tid AND trmm_client_name <> '" . esc($tname) . "'");
    }
}

// ---- Assets ----------------------------------------------------------------

// Only create assets under ITFlow clients that still exist and are not archived
$active_clients = [];
$res = mysqli_query($mysqli, "SELECT client_id FROM clients WHERE client_archived_at IS NULL");
while ($r = mysqli_fetch_row($res)) {
    $active_clients[intval($r[0])] = true;
}

// Existing assets known by their TRMM URL (including archived ones, so they are never recreated)
$by_uri = [];
$res = mysqli_query($mysqli,
    "SELECT asset_id, asset_name, asset_client_id, asset_description, asset_os, asset_uri, asset_archived_at,
            interface_id, interface_ip
     FROM assets LEFT JOIN asset_interfaces ON interface_asset_id = asset_id AND interface_primary = 1
     WHERE asset_uri LIKE '" . esc($web_url) . "/agents/%'");
while ($r = mysqli_fetch_assoc($res)) {
    $by_uri[$r['asset_uri']] = $r;
}

foreach ($agents as $a) {
    $tid = $name_to_trmm_id[trim($a['client_name'] ?? '')] ?? null;
    $m = $tid !== null ? ($map[$tid] ?? null) : null;
    if (!$m || intval($m['trmm_skip']) === 1) {
        $stats['agents_skipped']++;
        continue;
    }
    $cid = intval($m['client_id']);

    $uri = $web_url . '/agents/' . $a['agent_id'];
    $name = trim($a['hostname'] ?? '');
    $desc = trim((string)($a['description'] ?? ''));
    $os = trim((string)($a['operating_system'] ?? ''));
    $ip = pick_ip($a['local_ips'] ?? '');

    $asset = $by_uri[$uri] ?? null;

    // Adopt an asset created by hand (same name, same client, not linked to another agent)
    if (!$asset && isset($active_clients[$cid])) {
        $asset = mysqli_fetch_assoc(mysqli_query($mysqli,
            "SELECT asset_id, asset_name, asset_client_id, asset_description, asset_os, asset_uri, asset_archived_at, interface_id, interface_ip
             FROM assets LEFT JOIN asset_interfaces ON interface_asset_id = asset_id AND interface_primary = 1
             WHERE asset_client_id = $cid AND asset_name = '" . esc($name) . "'
               AND (asset_uri IS NULL OR asset_uri = '' OR asset_uri NOT LIKE '%/agents/%')
             ORDER BY asset_id LIMIT 1"));
        if ($asset) {
            $changes[] = "adopt existing asset $name ({$asset['asset_id']}) for agent";
            if (!$dry_run) {
                mysqli_query($mysqli, "UPDATE assets SET asset_uri = '" . esc($uri) . "' WHERE asset_id = " . intval($asset['asset_id']));
            }
        }
    }

    if (!$asset) {
        if ($cid <= 0 || !isset($active_clients[$cid])) {
            $stats['agents_skipped']++;
            continue;
        }
        [$purchase, $install] = $dry_run ? [null, null] : agent_dates($api_url, $api_key, $a['agent_id']);
        $model = trim(str_replace(["\r", "\n"], '', (string)($a['make_model'] ?? '')));
        if (strtolower($model) === 'unknown make/model') {
            $model = '';
        }
        $cpus = $a['cpu_model'] ?? [];
        $notes = count($cpus) . ' x ' . ($cpus[0] ?? '') . "\n" . ($a['graphics'] ?? '') . "\n";
        foreach ($a['physical_disks'] ?? [] as $disk) {
            $notes .= $disk . "\n";
        }
        $changes[] = "create asset $name for client $cid";
        $stats['assets_created']++;
        if (!$dry_run) {
            mysqli_query($mysqli, "INSERT INTO assets SET
                asset_name = '" . esc($name) . "', asset_description = '" . esc($desc) . "',
                asset_type = '" . esc(asset_type($a)) . "', asset_make = '', asset_model = '" . esc($model) . "',
                asset_serial = '" . esc($a['serial_number'] ?? '') . "', asset_os = '" . esc($os) . "',
                asset_uri = '" . esc($uri) . "', asset_status = 'Deployed', asset_notes = '" . esc($notes) . "',
                asset_purchase_date = " . ($purchase ? "'$purchase'" : "NULL") . ",
                asset_install_date = " . ($install ? "'$install'" : "NULL") . ",
                asset_client_id = $cid");
            $aid = mysqli_insert_id($mysqli);
            mysqli_query($mysqli, "INSERT INTO asset_interfaces SET interface_name = '1', interface_ip = '" . esc($ip) . "', interface_primary = 1, interface_asset_id = $aid");
            mysqli_query($mysqli, "INSERT INTO asset_history SET asset_history_status = 'Deployed', asset_history_description = '" . esc("Created by TRMM sync") . "', asset_history_asset_id = $aid");
            logAction("Asset", "Create", esc("$name via TRMM sync"), $cid, $aid);
        }
        continue;
    }

    if (!empty($asset['asset_archived_at'])) {
        continue;
    }

    // Keep description, OS and primary IP current
    $aid = intval($asset['asset_id']);
    $set = [];
    $what = [];
    if (trim((string)$asset['asset_description']) !== $desc) {
        $set[] = "asset_description = '" . esc($desc) . "'";
        $what[] = 'description';
    }
    // Ignore the monthly-changing build number: "Windows 11 Pro, 64 bit v25H2 (build 26200.7171)"
    $os_version = function ($s) { return trim(preg_replace('/\s*\(build [^)]*\)\s*$/i', '', trim((string)$s))); };
    if ($os !== '' && $os_version($asset['asset_os']) !== $os_version($os)) {
        $set[] = "asset_os = '" . esc($os) . "'";
        $what[] = 'OS';
    }
    $ip_changed = trim((string)$asset['interface_ip']) !== $ip;
    if ($ip_changed) {
        $what[] = 'IP';
    }
    if (!$what) {
        continue;
    }

    $changes[] = "update asset {$asset['asset_name']} ($aid): " . implode(', ', $what);
    $stats['assets_updated']++;
    if ($dry_run) {
        continue;
    }
    if ($set) {
        mysqli_query($mysqli, "UPDATE assets SET " . implode(', ', $set) . " WHERE asset_id = $aid");
    }
    if ($ip_changed) {
        if ($asset['interface_id']) {
            mysqli_query($mysqli, "UPDATE asset_interfaces SET interface_ip = '" . esc($ip) . "' WHERE interface_id = " . intval($asset['interface_id']));
        } else {
            mysqli_query($mysqli, "INSERT INTO asset_interfaces SET interface_name = '1', interface_ip = '" . esc($ip) . "', interface_primary = 1, interface_asset_id = $aid");
        }
    }
    mysqli_query($mysqli, "INSERT INTO asset_history SET asset_history_status = 'Deployed', asset_history_description = '" . esc("TRMM sync updated " . implode(', ', $what)) . "', asset_history_asset_id = $aid");
}

// ---- Summary ---------------------------------------------------------------

if ($verbose) {
    foreach ($changes as $c) {
        trmm_log(($dry_run ? '[dry-run] ' : '') . $c);
    }
}
$summary = sprintf('%d TRMM clients, %d agents: %d clients linked, %d clients created, %d assets created, %d assets updated, %d agents skipped',
    count($trmm_clients), count($agents), $stats['clients_linked'], $stats['clients_created'],
    $stats['assets_created'], $stats['assets_updated'], $stats['agents_skipped']);
trmm_log(($dry_run ? '[dry-run] ' : '') . $summary);

if (!$dry_run) {
    if ($changes) {
        logAction("TRMM Sync", "Run", esc($summary));
    }
    mysqli_query($mysqli, "UPDATE settings SET config_trmm_last_sync_at = NOW() WHERE company_id = 1");
}
