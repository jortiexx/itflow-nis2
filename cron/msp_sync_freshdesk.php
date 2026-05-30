<?php
/*
 * MSP Metrics - Freshdesk ticket sync.
 *
 * Pulls tickets + contacts from Freshdesk, attributes each ticket to a
 * msp_dim_customer via a layered matching chain, and aggregates per
 * (customer, day) into msp_fact_tickets_daily.
 *
 * Attribution chain (first hit wins):
 *   1. ticket.company_id  →  FD company name  →  fuzzy-name match against msp_dim_customer
 *   2. ticket requester's email domain  →  matches a FD company's domains[]  →  step 1
 *   3. ticket requester's email domain  →  matches an itflow contact email  →  client_id
 *                                                                          →  msp_dim_customer.itflow_client_id
 *   4. unattributed (logged in summary; not written)
 *
 * Re-runs are clean: today's snapshot is rebuilt from scratch each run so
 * rule changes propagate without stale rows lingering.
 */
chdir(dirname(__FILE__));
if (php_sapi_name() !== 'cli') die("CLI only.\n");

require_once "../config.php";
require_once "../includes/inc_set_timezone.php";
require_once "../functions.php";

function fd_log($m) { fwrite(STDOUT, '[' . date('Y-m-d H:i:s') . '] ' . $m . "\n"); }
function fd_err($m) { fwrite(STDERR, '[' . date('Y-m-d H:i:s') . '] ERROR: ' . $m . "\n"); }

$cfg = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_msp_freshdesk_domain, config_msp_freshdesk_api_key FROM settings WHERE company_id = 1"));
$dom = $cfg['config_msp_freshdesk_domain'] ?? '';
$key = $cfg['config_msp_freshdesk_api_key'] ?? '';
if (!$dom || !$key) { fd_err('Freshdesk not configured.'); exit(2); }

function fd_get(string $dom, string $key, string $path): array {
    $ch = curl_init("https://$dom/api/v2/$path");
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_USERPWD        => "$key:X",
        CURLOPT_TIMEOUT        => 60,
    ]);
    $raw  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($code !== 200) throw new RuntimeException("HTTP $code from $path: " . substr($raw, 0, 200));
    $j = json_decode($raw, true);
    if (!is_array($j)) throw new RuntimeException("non-array from $path");
    return $j;
}

function fd_paged(string $dom, string $key, string $resource, int $per = 100, int $max_pages = 50): array {
    $all = [];
    for ($p = 1; $p <= $max_pages; $p++) {
        $batch = fd_get($dom, $key, "$resource?per_page=$per&page=$p");
        if (!$batch) break;
        $all = array_merge($all, $batch);
        if (count($batch) < $per) break;
        usleep(200_000);
    }
    return $all;
}

function norm($name) {
    $n = mb_strtolower($name);
    $n = preg_replace('/\b(b\.?v\.?|n\.?v\.?|holding|gmbh|stichting|h\.o\.d\.n\.)\b/u', ' ', $n);
    $n = preg_replace('/[.,()\-_\/&]/u', ' ', $n);
    $n = preg_replace('/\s+/u', ' ', trim($n));
    return $n;
}

// ─── Pull everything we need from Freshdesk ────────────────────────────
try {
    $tickets    = fd_paged($dom, $key, 'tickets');
    $contacts   = fd_paged($dom, $key, 'contacts');
    $companies  = fd_paged($dom, $key, 'companies');
} catch (Throwable $e) {
    fd_err($e->getMessage()); exit(3);
}
fd_log('Fetched ' . count($tickets) . ' tickets, ' . count($contacts) . ' contacts, ' . count($companies) . ' companies');

$contact_by_id = [];
foreach ($contacts as $c) $contact_by_id[$c['id']] = $c;

// ─── Build attribution maps ────────────────────────────────────────────
// MSP customers by normalised name + itflow_client_id (for chain step 3).
$msp_by_norm_name = []; $msp_by_itflow_client = [];
$res = mysqli_query($mysqli, "SELECT customer_id, customer_name, itflow_client_id FROM msp_dim_customer");
while ($r = mysqli_fetch_assoc($res)) {
    $msp_by_norm_name[norm($r['customer_name'])] = intval($r['customer_id']);
    if (!empty($r['itflow_client_id'])) $msp_by_itflow_client[intval($r['itflow_client_id'])] = intval($r['customer_id']);
}
fd_log('MSP customers: ' . count($msp_by_norm_name) . ', with itflow link: ' . count($msp_by_itflow_client));

// FD-company-id  →  msp customer_id  (via fuzzy name match)
$fd_company_to_msp = [];
$fd_company_domains = [];   // domain  →  fd company id
foreach ($companies as $co) {
    if (isset($msp_by_norm_name[norm($co['name'])])) {
        $fd_company_to_msp[$co['id']] = $msp_by_norm_name[norm($co['name'])];
    }
    foreach ((array)($co['domains'] ?? []) as $d) {
        $fd_company_domains[strtolower($d)] = $co['id'];
    }
}
fd_log('FD companies auto-linked to MSP customers: ' . count($fd_company_to_msp) . ' of ' . count($companies));

// itflow contact email domain  →  itflow client_id (only when unambiguous)
$itflow_domain_to_client = [];
$res = mysqli_query($mysqli,
    "SELECT SUBSTRING_INDEX(contact_email, '@', -1) AS dom, MIN(contact_client_id) AS cid, COUNT(DISTINCT contact_client_id) AS n
     FROM contacts WHERE contact_email LIKE '%@%' AND contact_archived_at IS NULL
     GROUP BY dom HAVING n = 1");
while ($r = mysqli_fetch_assoc($res)) {
    $itflow_domain_to_client[strtolower($r['dom'])] = intval($r['cid']);
}
fd_log('itflow contact-email unambiguous domain mappings: ' . count($itflow_domain_to_client));

// ─── Walk tickets, attribute, aggregate per (customer, date) ──────────
$by_cust_date = [];   // [customer_id][date] => ['created'=>n, 'resolved'=>n]
$reasons = ['company_id' => 0, 'domain_fd' => 0, 'domain_itflow' => 0, 'unattributed' => 0];
foreach ($tickets as $t) {
    $cust_id = null;

    // 1. ticket.company_id  →  FD company  →  MSP customer
    if (!empty($t['company_id']) && isset($fd_company_to_msp[$t['company_id']])) {
        $cust_id = $fd_company_to_msp[$t['company_id']];
        $reasons['company_id']++;
    }

    // 2 + 3. domain-based lookups via requester contact
    if (!$cust_id) {
        $ct = $contact_by_id[$t['requester_id']] ?? null;
        $email = $ct['email'] ?? null;
        if ($email && ($at = strpos($email, '@')) !== false) {
            $d = strtolower(substr($email, $at + 1));
            // 2. domain  →  FD company  →  MSP customer
            if (isset($fd_company_domains[$d], $fd_company_to_msp[$fd_company_domains[$d]])) {
                $cust_id = $fd_company_to_msp[$fd_company_domains[$d]];
                $reasons['domain_fd']++;
            }
            // 3. domain  →  itflow client  →  MSP customer
            elseif (isset($itflow_domain_to_client[$d], $msp_by_itflow_client[$itflow_domain_to_client[$d]])) {
                $cust_id = $msp_by_itflow_client[$itflow_domain_to_client[$d]];
                $reasons['domain_itflow']++;
            }
        }
    }
    if (!$cust_id) { $reasons['unattributed']++; continue; }

    $created_date = substr($t['created_at'], 0, 10);
    if (!isset($by_cust_date[$cust_id][$created_date])) $by_cust_date[$cust_id][$created_date] = ['created'=>0, 'resolved'=>0];
    $by_cust_date[$cust_id][$created_date]['created']++;

    // Resolved: status 4 = Resolved, 5 = Closed. updated_at is the closest proxy
    // for "when did this hit a resolved/closed state" in the bulk-fetch view.
    if (in_array(intval($t['status']), [4, 5], true)) {
        $resolved_date = substr($t['updated_at'], 0, 10);
        if (!isset($by_cust_date[$cust_id][$resolved_date])) $by_cust_date[$cust_id][$resolved_date] = ['created'=>0, 'resolved'=>0];
        $by_cust_date[$cust_id][$resolved_date]['resolved']++;
    }
}
fd_log("Attribution: company_id={$reasons['company_id']}, domain_fd={$reasons['domain_fd']}, domain_itflow={$reasons['domain_itflow']}, unattributed={$reasons['unattributed']}");

// ─── Write fact rows ───────────────────────────────────────────────────
// Wipe-and-rewrite for the full date range we computed, so re-runs after
// attribution-rule changes (e.g. new domain mapping) produce clean rows.
$all_dates = [];
foreach ($by_cust_date as $by_date) foreach (array_keys($by_date) as $d) $all_dates[$d] = true;
if ($all_dates) {
    $min = min(array_keys($all_dates));
    $max = max(array_keys($all_dates));
    mysqli_query($mysqli, "DELETE FROM msp_fact_tickets_daily WHERE entry_date BETWEEN '$min' AND '$max'");
}

$written = 0;
foreach ($by_cust_date as $cid => $by_date) {
    foreach ($by_date as $date => $c) {
        $cid_e = intval($cid);
        $date_e = mysqli_real_escape_string($mysqli, $date);
        $created = intval($c['created']);
        $resolved = intval($c['resolved']);
        mysqli_query($mysqli, "INSERT INTO msp_fact_tickets_daily
            (customer_id, entry_date, tickets_created, tickets_resolved)
            VALUES ($cid_e, '$date_e', $created, $resolved)
            ON DUPLICATE KEY UPDATE
                tickets_created  = VALUES(tickets_created),
                tickets_resolved = VALUES(tickets_resolved)");
        $written++;
    }
}

mysqli_query($mysqli, "UPDATE settings SET config_msp_last_sync_freshdesk_at = NOW() WHERE company_id = 1");
fd_log("Wrote $written fact rows across " . count($by_cust_date) . " customers");
exit(0);
