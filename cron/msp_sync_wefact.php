<?php
/*
 * MSP Metrics - WeFact subscription sync
 *
 * Pulls active subscriptions via WeFact API, derives per-customer monthly
 * MRR + workplace count, and writes one snapshot row per customer per day
 * to msp_fact_subscription_snapshot (unique on customer+date so re-runs
 * within the same day are idempotent: ON DUPLICATE KEY UPDATE).
 *
 * Suggested crontab (run once at 02:00 on the monthly billing day, or
 * daily for a denser growth curve):
 *   0 2 * * *  /usr/bin/php /var/www/<site>/cron/msp_sync_wefact.php
 *
 * Reads:  settings.config_msp_wefact_api_url, ...api_key
 * Writes: msp_dim_customer (upsert), msp_fact_subscription_snapshot (upsert),
 *         settings.config_msp_last_sync_wefact_at
 *
 * Werkplekken: we count line-items whose product code contains "WERKPLEK"
 * (case-insensitive) and sum their quantities per subscription. Adjust
 * WORKPLACE_CODE_PATTERN below if your product naming differs.
 */

chdir(dirname(__FILE__));
if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

require_once "../config.php";
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

const WORKPLACE_CODE_PATTERN = '/werkplek/i';

// Subscription Groups that are NOT real recurring revenue, even though
// WeFact has them flagged as active subscriptions. Case-insensitive
// substring match against the Group field. Extend as new non-MRR groups
// surface in WeFact.
//
// Per business rule: everything in WeFact subscriptions counts as MRR
// EXCEPT fixed-end project instalments ("Termijnen ..."). Prepaid bundles
// like strippenkaart do count — they're still recurring cashflow.
const NON_MRR_GROUP_PATTERNS = [
    '/termijnen/i',     // "Termijnen migratieproject" etc — fixed-end project instalments
];

function wefact_log($msg) { fwrite(STDOUT, '[' . date('Y-m-d H:i:s') . '] ' . $msg . "\n"); }
function wefact_err($msg) { fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $msg . "\n"); }

// Load API config.
$cfg = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_msp_wefact_api_url, config_msp_wefact_api_key
     FROM settings WHERE company_id = 1 LIMIT 1"));
// WeFact's API endpoint *requires* the trailing slash (otherwise responds 301
// to itself + same URL). Don't strip it — ensure exactly one.
$api_url = rtrim($cfg['config_msp_wefact_api_url'] ?? '', '/') . '/';
$api_key = $cfg['config_msp_wefact_api_key'] ?? '';

if (!$api_url || !$api_key) {
    wefact_err('WeFact API URL or key not configured (see Admin → MSP Metrics).');
    exit(2);
}

/**
 * POST a JSON-RPC-style call to WeFact v2 and return the decoded body.
 * Throws on transport error; caller checks $resp['status'] === 'success'.
 */
function wefact_call(string $api_url, string $api_key, string $controller, string $action, array $params = []): array {
    $body = json_encode([
        'api_key'    => $api_key,
        'controller' => $controller,
        'action'     => $action,
    ] + $params);

    $ch = curl_init($api_url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS      => 3,
    ]);
    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($raw === false) {
        throw new RuntimeException("curl error: $err");
    }
    if ($code < 200 || $code >= 300) {
        throw new RuntimeException("HTTP $code from WeFact: " . substr($raw, 0, 400));
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('non-JSON response: ' . substr($raw, 0, 400));
    }
    return $decoded;
}

/**
 * Number of months one WeFact billing cycle covers, so periodic amounts
 * can be normalised to a per-month axis. WeFact's `Periodic` is a letter
 * code (Dutch shorthand), not an integer:
 *   m = maand,  k = kwartaal,  h = halfjaar,  j = jaar
 * We accept the legacy numeric forms too, just in case.
 */
function periodic_months(string $period): int {
    $p = strtolower(trim($period));
    return match (true) {
        in_array($p, ['m', '1',  'monthly',    'maandelijks', 'maand'],          true) => 1,
        in_array($p, ['k', '3',  'quarterly',  'kwartaal',    'per kwartaal'],   true) => 3,
        in_array($p, ['h', '6',  'halfyearly', 'halfjaarlijks'],                 true) => 6,
        in_array($p, ['j', '12', 'yearly',     'jaarlijks',   'per jaar'],       true) => 12,
        default => 1, // unknown unit -> assume monthly so we never inflate
    };
}

try {
    $resp = wefact_call($api_url, $api_key, 'subscription', 'list', [
        'params' => ['Status' => 'active']
    ]);
} catch (Throwable $e) {
    wefact_err('subscription/list failed: ' . $e->getMessage());
    exit(3);
}

if (($resp['status'] ?? '') !== 'success') {
    wefact_err('WeFact returned non-success: ' . json_encode($resp));
    exit(4);
}

$subscriptions = $resp['subscriptions'] ?? [];
wefact_log('Fetched ' . count($subscriptions) . ' subscriptions');

// Aggregate per debtor. WeFact's subscription/list returns one row PER
// subscription line already (each row has Identifier, DebtorCode,
// CompanyName, ProductCode, Description, Group, Number, PriceExcl, Periodic,
// AmountExcl, Status). No per-subscription detail call needed.
$by_debtor = [];   // debtor_code => ['name','mrr','workplaces','count']

$skipped_non_mrr = 0;
foreach ($subscriptions as $s) {
    $debtor_id   = (string)($s['DebtorCode'] ?? '');
    $debtor_name = (string)($s['CompanyName'] ?? ('debtor ' . $debtor_id));
    if ($debtor_id === '') {
        wefact_err('subscription ' . ($s['Identifier'] ?? '?') . ' has no DebtorCode, skipping');
        continue;
    }

    // Drop non-recurring rows entirely — they shouldn't count toward MRR,
    // subscription_count, or workplaces.
    $group = (string)($s['Group'] ?? '');
    foreach (NON_MRR_GROUP_PATTERNS as $pat) {
        if (preg_match($pat, $group)) {
            $skipped_non_mrr++;
            continue 2;
        }
    }

    if (!isset($by_debtor[$debtor_id])) {
        $by_debtor[$debtor_id] = [
            'name' => $debtor_name, 'mrr' => 0.0, 'workplaces' => 0, 'count' => 0,
        ];
    }
    $by_debtor[$debtor_id]['count']++;

    // AmountExcl already includes Number × PriceExcl for this subscription line.
    // Normalise to monthly: monthly = periodic amount / months in cycle.
    $months_per_cycle = periodic_months((string)($s['Periodic'] ?? 'm'));
    $line_amount      = (float)($s['AmountExcl'] ?? ((float)($s['PriceExcl'] ?? 0) * (float)($s['Number'] ?? 1)));
    $by_debtor[$debtor_id]['mrr'] += $line_amount / $months_per_cycle;

    // Workplaces: match the configurable pattern against Group / ProductCode /
    // Description. Sum the Number (quantity) field. Adjust pattern at top
    // of file if your product naming differs.
    $haystack = ($s['Group'] ?? '') . ' ' . ($s['ProductCode'] ?? '') . ' ' . ($s['Description'] ?? '');
    if (preg_match(WORKPLACE_CODE_PATTERN, $haystack)) {
        $by_debtor[$debtor_id]['workplaces'] += (int)($s['Number'] ?? 0);
    }
}

// Persist: dim_customer upsert + fact_subscription_snapshot upsert.
//
// We delete today's snapshots first so that re-runs after a rule change
// (e.g. extending NON_MRR_GROUP_PATTERNS) produce a clean state. Without
// this, a customer that used to be included but is now wholly excluded
// would keep yesterday's-or-earlier numbers in today's row.
//
// Also reset has_active_subscription = 0 across the board; we'll flip it
// back to 1 for any debtor we see in this run. Net effect: customers
// whose subs were all cancelled / archived since last sync correctly
// flip to inactive, but stay in the dim table for transfer-source use.
$snapshot_date = date('Y-m-d');
mysqli_query($mysqli, "DELETE FROM msp_fact_subscription_snapshot WHERE snapshot_date = '$snapshot_date'");
mysqli_query($mysqli, "UPDATE msp_dim_customer SET has_active_subscription = 0");

$cust_seen = $rows_written = 0;
foreach ($by_debtor as $debtor_id => $agg) {
    $debtor_e = mysqli_real_escape_string($mysqli, $debtor_id);
    $name_e   = mysqli_real_escape_string($mysqli, $agg['name']);

    mysqli_query($mysqli, "INSERT INTO msp_dim_customer (customer_name, source_wefact_debtor_id, has_active_subscription)
        VALUES ('$name_e', '$debtor_e', 1)
        ON DUPLICATE KEY UPDATE
            customer_name           = VALUES(customer_name),
            has_active_subscription = 1");
    $cust_row = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT customer_id FROM msp_dim_customer WHERE source_wefact_debtor_id = '$debtor_e' LIMIT 1"));
    $customer_id = intval($cust_row['customer_id']);
    if ($customer_id <= 0) { wefact_err("could not resolve customer_id for debtor $debtor_id"); continue; }
    $cust_seen++;

    $mrr_e        = number_format($agg['mrr'], 2, '.', '');
    $workplaces_e = intval($agg['workplaces']);
    $count_e      = intval($agg['count']);

    mysqli_query($mysqli, "INSERT INTO msp_fact_subscription_snapshot
        (customer_id, snapshot_date, mrr_eur, workplaces_count, subscription_count)
        VALUES ($customer_id, '$snapshot_date', $mrr_e, $workplaces_e, $count_e)
        ON DUPLICATE KEY UPDATE
            mrr_eur = VALUES(mrr_eur),
            workplaces_count = VALUES(workplaces_count),
            subscription_count = VALUES(subscription_count)");
    $rows_written++;
}

// ─── Backfill historical (no-active-sub) customers from invoice/list.
// debtors that have ever been billed = real historical customers. They
// stay in dim_customer with has_active_subscription = 0 so the transfer
// dropdown can still point to them and the cohort chart shows them in
// their onboarding month.
$historical_added = 0;
$offset = 0; $page = 500; $seen_codes = [];
for ($i = 0; $i < 50; $i++) {
    try {
        $r = wefact_call($api_url, $api_key, 'invoice', 'list', ['offset' => $offset, 'limit' => $page]);
    } catch (Throwable $e) {
        wefact_err('invoice/list page ' . $i . ' failed: ' . $e->getMessage());
        break;
    }
    $batch = $r['invoices'] ?? [];
    if (!$batch) break;
    foreach ($batch as $inv) {
        $dc = (string)($inv['DebtorCode'] ?? '');
        $nm = (string)($inv['CompanyName'] ?? ('debtor ' . $dc));
        if ($dc === '' || isset($seen_codes[$dc])) continue;
        $seen_codes[$dc] = true;
        $dc_e = mysqli_real_escape_string($mysqli, $dc);
        $nm_e = mysqli_real_escape_string($mysqli, $nm);
        $result = mysqli_query($mysqli, "INSERT IGNORE INTO msp_dim_customer
            (customer_name, source_wefact_debtor_id, has_active_subscription)
            VALUES ('$nm_e', '$dc_e', 0)");
        if ($result && mysqli_affected_rows($mysqli) > 0) $historical_added++;
    }
    if (count($batch) < $page) break;
    $offset += $page;
}
wefact_log("Historical customers (invoiced-only, no current sub) added: $historical_added");

// ─── Backfill wefact_created_at for any customer that doesn't have one yet.
// One-time cost on first run (1 call per existing customer); thereafter
// only new customers cost an extra call. WeFact's debtor.Created is the
// authoritative onboarding date — pre-migration customers all share the
// migration date, which is semantically correct.
$missing = mysqli_query($mysqli,
    "SELECT customer_id, source_wefact_debtor_id FROM msp_dim_customer
     WHERE wefact_created_at IS NULL AND source_wefact_debtor_id IS NOT NULL");
$created_filled = 0;
while ($row = mysqli_fetch_assoc($missing)) {
    try {
        $r = wefact_call($api_url, $api_key, 'debtor', 'show', ['DebtorCode' => $row['source_wefact_debtor_id']]);
    } catch (Throwable $e) {
        wefact_err('debtor/show ' . $row['source_wefact_debtor_id'] . ' failed: ' . $e->getMessage());
        continue;
    }
    $created = $r['debtor']['Created'] ?? null;
    if (!$created) continue;
    $created_e = mysqli_real_escape_string($mysqli, $created);
    $cid = intval($row['customer_id']);
    mysqli_query($mysqli, "UPDATE msp_dim_customer SET wefact_created_at = '$created_e' WHERE customer_id = $cid");
    $created_filled++;
    usleep(50_000); // 50ms — gentle on WeFact's API
}

mysqli_query($mysqli, "UPDATE settings SET config_msp_last_sync_wefact_at = NOW() WHERE company_id = 1");

wefact_log("done — customers seen: $cust_seen, snapshots upserted: $rows_written, non-MRR rows skipped: $skipped_non_mrr, wefact_created_at backfilled: $created_filled");
exit(0);
