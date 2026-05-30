<?php
/*
 * One-off (rerunnable): match msp_dim_customer rows to itflow clients by
 * normalised name, and set msp_dim_customer.itflow_client_id where there
 * is exactly one match. Ambiguous (multiple itflow clients normalise to
 * the same key) and unmatched rows are reported but left alone, so a
 * human can decide.
 *
 * Triggered manually from /admin/msp_metrics_settings.php (button) and
 * also runnable from cron / SSH.
 */
chdir(dirname(__FILE__));
$cli = (php_sapi_name() === 'cli');
require_once "../config.php";
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

function norm($name) {
    $n = mb_strtolower($name);
    $n = preg_replace('/\b(b\.?v\.?|n\.?v\.?|holding|gmbh|stichting|h\.o\.d\.n\.)\b/u', ' ', $n);
    $n = preg_replace('/[.,()\-_\/&]/u', ' ', $n);
    $n = preg_replace('/\s+/u', ' ', trim($n));
    return $n;
}

// Build itflow index: norm-name -> [client_id, ...]
$itflow_idx = [];
$res = mysqli_query($mysqli, "SELECT client_id, client_name FROM clients WHERE client_archived_at IS NULL");
while ($r = mysqli_fetch_assoc($res)) {
    $k = norm($r['client_name']);
    if ($k === '') continue;
    $itflow_idx[$k][] = [intval($r['client_id']), $r['client_name']];
}

// Scan dim_customer.
$linked = $ambiguous = $unmatched = $already_linked = 0;
$report = [];
$res = mysqli_query($mysqli, "SELECT customer_id, customer_name, itflow_client_id FROM msp_dim_customer");
while ($r = mysqli_fetch_assoc($res)) {
    if (!empty($r['itflow_client_id'])) { $already_linked++; continue; }
    $k = norm($r['customer_name']);
    $candidates = $itflow_idx[$k] ?? [];
    if (count($candidates) === 1) {
        $cid_itflow = $candidates[0][0];
        $cid_msp    = intval($r['customer_id']);
        mysqli_query($mysqli, "UPDATE msp_dim_customer SET itflow_client_id = $cid_itflow WHERE customer_id = $cid_msp");
        $linked++;
    } elseif (count($candidates) > 1) {
        $ambiguous++;
        $report[] = ['type' => 'ambiguous', 'msp' => $r['customer_name'], 'matches' => array_map(fn($c) => $c[1], $candidates)];
    } else {
        $unmatched++;
        $report[] = ['type' => 'unmatched', 'msp' => $r['customer_name']];
    }
}

logAction('MSP Metrics', 'Link', "itflow client mapping: $linked linked, $ambiguous ambiguous, $unmatched unmatched");

$summary = "Linked: $linked  |  Already linked: $already_linked  |  Ambiguous: $ambiguous  |  Unmatched: $unmatched";

if ($cli) {
    echo "$summary\n";
    foreach (array_slice($report, 0, 30) as $r) {
        if ($r['type'] === 'ambiguous')
            echo "  AMBIGUOUS: {$r['msp']}  ->  " . implode(' | ', $r['matches']) . "\n";
        else
            echo "  UNMATCHED: {$r['msp']}\n";
    }
    if (count($report) > 30) echo "  ... and " . (count($report) - 30) . " more\n";
    exit(0);
}

// HTTP context (from admin button): set a flash and redirect back.
flash_alert("itflow mapping: $summary");
redirect('msp_metrics_settings.php');
