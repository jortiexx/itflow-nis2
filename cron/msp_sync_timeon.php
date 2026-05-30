<?php
/*
 * MSP Metrics - TimeOn timesheet sync.
 *
 * Auth flow (TimeOn-specific OAuth2 variant):
 *   POST https://api.timeon.nl/token?grant_type=apitoken&token=<APITOKEN>
 *   -> { access_token, expires_in: 14400 (4h) }
 *   Then send `Authorization: Bearer <access_token>` on every API call.
 *
 * What it does:
 *   1. Trade the persistent API key for a short-lived access_token
 *   2. Page through /api/customer/list, populate source_timeon_customer_id
 *      on existing msp_dim_customer rows (match by name; create stub rows
 *      for TimeOn-only customers so their hours can be attributed)
 *   3. Page through /api/user/search, upsert msp_dim_employee
 *   4. Pull hour data for the last N days (env LOOKBACK_DAYS, default 60).
 *      Hours come grouped by day; each hour row has userID/customerID/seconds
 *      and a billable seconds split. Aggregate into msp_fact_hours_daily.
 *
 * Idempotent: today's date range is wiped before writing new rows.
 */
chdir(dirname(__FILE__));
if (php_sapi_name() !== 'cli') die("CLI only.\n");

require_once "../config.php";
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

function to_log($m) { fwrite(STDOUT, '[' . date('Y-m-d H:i:s') . '] ' . $m . "\n"); }
function to_err($m) { fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $m . "\n"); }

$cfg = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_msp_timeon_api_url, config_msp_timeon_api_key FROM settings WHERE company_id = 1"));
$url = rtrim($cfg['config_msp_timeon_api_url'] ?? 'https://api.timeon.nl', '/');
$key = $cfg['config_msp_timeon_api_key'] ?? '';
if (!$key) { to_err('TimeOn API key not configured.'); exit(2); }

$LOOKBACK_DAYS = intval(getenv('LOOKBACK_DAYS') ?: '60');

// ─── Token exchange ────────────────────────────────────────────────────
$ch = curl_init("$url/token?grant_type=apitoken&token=" . urlencode($key));
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_TIMEOUT => 30]);
$tok = json_decode(curl_exec($ch), true);
if (!is_array($tok) || empty($tok['access_token'])) {
    to_err('token exchange failed: ' . json_encode($tok));
    exit(3);
}
$access_token = $tok['access_token'];
to_log('Got access_token (expires_in=' . ($tok['expires_in'] ?? '?') . 's)');

function to_call(string $url, string $access_token, string $path, $body): array {
    $ch = curl_init("$url/$path");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_POSTFIELDS     => json_encode($body),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json', "Authorization: Bearer $access_token"],
    ]);
    $raw  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) throw new RuntimeException("HTTP $code from $path: " . substr($raw, 0, 200));
    $j = json_decode($raw, true);
    if (!is_array($j)) throw new RuntimeException("non-JSON from $path");
    return $j['resultObject'] ?? $j;
}

function norm($name) {
    $n = mb_strtolower($name);
    $n = preg_replace('/\b(b\.?v\.?|n\.?v\.?|holding|gmbh|stichting|h\.o\.d\.n\.)\b/u', ' ', $n);
    $n = preg_replace('/[.,()\-_\/&]/u', ' ', $n);
    $n = preg_replace('/\s+/u', ' ', trim($n));
    return $n;
}

// ─── Customers — index ALL but only persist what we need ─────────────
// TimeOn keeps every customer record ever, including dupes/renamed/dead
// ("(Gebruik X!)", "*niet gebruiken*"). 523 records but typically <50 are
// actively in use. We index the full list so we can look up by ID when
// processing hour entries, but only INSERT dim rows for customers that
// either (a) already exist in msp_dim_customer (link them) or (b) have
// hours logged in the lookback window (= really used).
$all_customers = []; $page = 1;
for ($i = 0; $i < 50; $i++) {
    try {
        $r = to_call($url, $access_token, 'api/customer/list', ['page' => $page, 'pageSize' => 100]);
    } catch (Throwable $e) { to_err('customer/list page ' . $page . ': ' . $e->getMessage()); break; }
    $items = $r['items'] ?? [];
    if (!$items) break;
    $all_customers = array_merge($all_customers, $items);
    if (count($items) < 100) break;
    $page++;
    usleep(150_000);
}
to_log('Fetched ' . count($all_customers) . ' TimeOn customers (full universe)');

// Index by TimeOn ID — used during hour processing to know name + match later.
$timeon_idx = [];
foreach ($all_customers as $tc) $timeon_idx[intval($tc['customerID'])] = $tc;

// Existing dim by normalised name + by source_timeon_customer_id.
$msp_by_name = []; $msp_by_timeon_id = [];
$res = mysqli_query($mysqli, "SELECT customer_id, customer_name, source_timeon_customer_id FROM msp_dim_customer");
while ($r = mysqli_fetch_assoc($res)) {
    $msp_by_name[norm($r['customer_name'])] = intval($r['customer_id']);
    if ($r['source_timeon_customer_id']) $msp_by_timeon_id[intval($r['source_timeon_customer_id'])] = intval($r['customer_id']);
}

// Backfill source_timeon_customer_id on existing rows that match by name.
// Don't create stubs here — we'll create them lazily during hour processing
// for customers that actually have hours.
$linked = 0;
foreach ($all_customers as $tc) {
    $name = trim($tc['name'] ?? '');
    if (!$name) continue;
    $cid = $msp_by_name[norm($name)] ?? null;
    if (!$cid) continue;
    $tcid = intval($tc['customerID']);
    if (!isset($msp_by_timeon_id[$tcid])) {
        mysqli_query($mysqli, "UPDATE msp_dim_customer
            SET source_timeon_customer_id = '$tcid'
            WHERE customer_id = $cid AND source_timeon_customer_id IS NULL");
        $msp_by_timeon_id[$tcid] = $cid;
        $linked++;
    }
}
to_log("Customer linkage: $linked existing rows backfilled with TimeOn ID");

// Helper: get-or-create msp dim row for a TimeOn customer that has hours.
// Falls back to creating a stub for TimeOn-only customers, but ONLY when
// we have evidence (hours) that they're real.
$timeon_to_msp = $msp_by_timeon_id;   // start with existing links
$created_dim = 0;
$ensure_customer = function (int $tcid) use ($mysqli, $timeon_idx, &$msp_by_name, &$timeon_to_msp, &$created_dim) {
    if (isset($timeon_to_msp[$tcid])) return $timeon_to_msp[$tcid];
    $tc = $timeon_idx[$tcid] ?? null;
    if (!$tc) return null;
    $name = trim($tc['name'] ?? '');
    if (!$name) return null;
    $k = norm($name);
    if (isset($msp_by_name[$k])) {
        $cid = $msp_by_name[$k];
        mysqli_query($mysqli, "UPDATE msp_dim_customer SET source_timeon_customer_id = '$tcid'
            WHERE customer_id = $cid AND source_timeon_customer_id IS NULL");
        $timeon_to_msp[$tcid] = $cid;
        return $cid;
    }
    $name_e = mysqli_real_escape_string($mysqli, $name);
    mysqli_query($mysqli, "INSERT INTO msp_dim_customer
        (customer_name, source_timeon_customer_id, has_active_subscription)
        VALUES ('$name_e', '$tcid', 0)");
    $cid = mysqli_insert_id($mysqli);
    $msp_by_name[$k] = $cid;
    $timeon_to_msp[$tcid] = $cid;
    $created_dim++;
    return $cid;
};

// ─── Users (employees) ───────────────────────────────────────────────
// /api/user/search returns the org's users.
try {
    $users_resp = to_call($url, $access_token, 'api/user/search', ['activeOnly' => true]);
} catch (Throwable $e) { to_err('user/search: ' . $e->getMessage()); $users_resp = []; }
$users = $users_resp['items'] ?? (is_array($users_resp) ? $users_resp : []);
to_log('Fetched ' . count($users) . ' TimeOn users');

$timeon_user_to_emp = [];
foreach ($users as $u) {
    $uid = intval($u['userID'] ?? 0);
    if (!$uid) continue;
    $name = trim($u['name'] ?? '') ?: "user $uid";
    $name_e = mysqli_real_escape_string($mysqli, $name);
    mysqli_query($mysqli, "INSERT INTO msp_dim_employee (employee_name, source_timeon_user_id, is_active)
        VALUES ('$name_e', '$uid', 1)
        ON DUPLICATE KEY UPDATE employee_name = VALUES(employee_name), is_active = 1");
    $row = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT employee_id FROM msp_dim_employee WHERE source_timeon_user_id = '$uid' LIMIT 1"));
    if ($row) $timeon_user_to_emp[$uid] = intval($row['employee_id']);
}

// ─── Hours ────────────────────────────────────────────────────────────
$from = gmdate('Y-m-d\TH:i:s\Z', strtotime("-$LOOKBACK_DAYS days"));
$to   = gmdate('Y-m-d\TH:i:s\Z');
$hours_body = ['filter' => ['from' => $from, 'to' => $to]];

try {
    $hr = to_call($url, $access_token, 'api/hour/list', $hours_body);
} catch (Throwable $e) { to_err('hour/list: ' . $e->getMessage()); exit(4); }

// Walk groups (= days) and individual hourList entries. Aggregate per
// (customer_id, employee_id, entry_date).
$agg = []; $no_cust = $no_emp = 0;
foreach (($hr['groups'] ?? []) as $day_group) {
    $date = $day_group['shortTitle'] ?? null;
    if (!$date) continue;
    foreach (($day_group['hourList'] ?? []) as $h) {
        $tcid = intval($h['customerID'] ?? 0);
        $tuid = intval($h['userID']     ?? 0);
        $cid  = $tcid > 0 ? $ensure_customer($tcid) : null;
        $eid  = $timeon_user_to_emp[$tuid] ?? null;
        if (!$cid) { $no_cust++; continue; }
        if (!$eid) { $no_emp++;  continue; }
        $secs        = intval($h['seconds']         ?? 0);
        $secs_billable = intval($h['secondsBillable'] ?? 0);
        $key = "$cid|$eid|$date";
        if (!isset($agg[$key])) $agg[$key] = ['cid' => $cid, 'eid' => $eid, 'date' => $date, 'sec_b' => 0, 'sec_nb' => 0];
        $agg[$key]['sec_b']  += $secs_billable;
        $agg[$key]['sec_nb'] += ($secs - $secs_billable);
    }
}
to_log("Aggregated " . count($agg) . " (customer,employee,date) tuples — skipped no-customer: $no_cust, no-employee: $no_emp");
to_log("Created stubs for $created_dim TimeOn customers with hours that weren't in dim yet");

// Wipe the lookback window before re-write so rule changes propagate.
$from_date = date('Y-m-d', strtotime("-$LOOKBACK_DAYS days"));
$to_date   = date('Y-m-d');
mysqli_query($mysqli, "DELETE FROM msp_fact_hours_daily WHERE entry_date BETWEEN '$from_date' AND '$to_date'");

$written = 0;
foreach ($agg as $row) {
    $hb  = number_format($row['sec_b']  / 3600.0, 2, '.', '');
    $hnb = number_format($row['sec_nb'] / 3600.0, 2, '.', '');
    $cid = $row['cid']; $eid = $row['eid']; $d = mysqli_real_escape_string($mysqli, $row['date']);
    mysqli_query($mysqli, "INSERT INTO msp_fact_hours_daily
        (customer_id, employee_id, entry_date, hours_billable, hours_nonbillable)
        VALUES ($cid, $eid, '$d', $hb, $hnb)
        ON DUPLICATE KEY UPDATE
            hours_billable    = VALUES(hours_billable),
            hours_nonbillable = VALUES(hours_nonbillable)");
    $written++;
}

mysqli_query($mysqli, "UPDATE settings SET config_msp_last_sync_timeon_at = NOW() WHERE company_id = 1");
to_log("Wrote $written msp_fact_hours_daily rows");
exit(0);
