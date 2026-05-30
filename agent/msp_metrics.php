<?php
require_once "includes/inc_all.php";

if (!$config_module_enable_msp_metrics) {
    flash_alert('MSP Metrics module is disabled.', 'error');
    redirect('dashboard.php');
}
enforceUserPermission('module_reporting');

// ─── Latest snapshot date per customer ────────────────────────────────
// We want the most-recent snapshot per customer for the headline numbers,
// not a sum across all snapshot dates.
$latest = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT MAX(snapshot_date) AS d FROM msp_fact_subscription_snapshot"));
$latest_date = $latest['d'];

if (!$latest_date) {
    ?>
    <div class="card card-dark">
        <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-chart-pie mr-2"></i>MSP Metrics</h3></div>
        <div class="card-body">
            <div class="alert alert-info">
                <strong>No data yet.</strong> Configure API keys at
                <a href="/admin/msp_metrics_settings.php">Admin → MSP Metrics</a>, then run a sync:
                <pre class="mt-2 mb-0 small">php /var/www/&lt;site&gt;/cron/msp_sync_wefact.php</pre>
            </div>
        </div>
    </div>
    <?php
    require_once "../includes/footer.php";
    exit;
}

// Headline aggregates (latest snapshot per customer).
$totals = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COUNT(*) AS customers,
            COALESCE(SUM(mrr_eur),0) AS mrr_total,
            COALESCE(SUM(workplaces_count),0) AS workplaces_total,
            COALESCE(SUM(subscription_count),0) AS subs_total
     FROM msp_fact_subscription_snapshot WHERE snapshot_date = '$latest_date'"));

// Top 10 customers by MRR for the chart.
$top = mysqli_query($mysqli,
    "SELECT c.customer_name, s.mrr_eur, s.workplaces_count, s.subscription_count
     FROM msp_fact_subscription_snapshot s
     JOIN msp_dim_customer c USING (customer_id)
     WHERE s.snapshot_date = '$latest_date'
     ORDER BY s.mrr_eur DESC LIMIT 10");
$top_labels = []; $top_mrr = []; $top_workplaces = [];
while ($r = mysqli_fetch_assoc($top)) {
    $top_labels[]     = $r['customer_name'];
    $top_mrr[]        = floatval($r['mrr_eur']);
    $top_workplaces[] = intval($r['workplaces_count']);
}

// MRR trend across all snapshot dates (one row per date).
$trend = mysqli_query($mysqli,
    "SELECT snapshot_date,
            SUM(mrr_eur)          AS mrr_sum,
            SUM(workplaces_count) AS wp_sum,
            COUNT(*)              AS cust_count
     FROM msp_fact_subscription_snapshot
     GROUP BY snapshot_date
     ORDER BY snapshot_date");
$trend_labels = []; $trend_mrr = []; $trend_wp = []; $trend_cust = [];
while ($r = mysqli_fetch_assoc($trend)) {
    $trend_labels[] = $r['snapshot_date'];
    $trend_mrr[]    = floatval($r['mrr_sum']);
    $trend_wp[]     = intval($r['wp_sum']);
    $trend_cust[]   = intval($r['cust_count']);
}

// All customers for the table. LEFT JOIN to the predecessor row so we can
// render an "↶ from X" marker, and to the successor (this customer is the
// "transferred_from" of another) so we can show "→ to Y".
$all = mysqli_query($mysqli,
    "SELECT c.customer_id, c.customer_name, c.itflow_client_id,
            c.transferred_from_customer_id, c.transferred_at,
            pred.customer_name AS pred_name,
            succ.customer_id   AS succ_id,
            succ.customer_name AS succ_name,
            s.mrr_eur, s.workplaces_count, s.subscription_count
     FROM msp_fact_subscription_snapshot s
     JOIN msp_dim_customer c USING (customer_id)
     LEFT JOIN msp_dim_customer pred ON pred.customer_id = c.transferred_from_customer_id
     LEFT JOIN msp_dim_customer succ ON succ.transferred_from_customer_id = c.customer_id
     WHERE s.snapshot_date = '$latest_date'
     ORDER BY s.mrr_eur DESC");

// ─── Growth: new customers per month + cumulative curve ───────────────
// wefact_created_at = the date WeFact registered this debtor. Pre-migration
// customers all share the migration date — semantically correct.
//
// Transferred customers (transferred_from_customer_id NOT NULL) are EXCLUDED
// from the new-customer cohort: they're a continuation of an existing
// relationship, not net new growth. We still surface them separately so
// the user can see "1 transfer in mei" alongside the bar chart.
$cohort = mysqli_query($mysqli,
    "SELECT DATE_FORMAT(wefact_created_at, '%Y-%m') AS month,
            SUM(transferred_from_customer_id IS NULL)     AS new_customers,
            SUM(transferred_from_customer_id IS NOT NULL) AS transferred_in
     FROM msp_dim_customer
     WHERE wefact_created_at IS NOT NULL
     GROUP BY month ORDER BY month");
$cohort_labels = []; $cohort_new = []; $cohort_cum = []; $cohort_transferred = [];
$running = 0;
while ($r = mysqli_fetch_assoc($cohort)) {
    $cohort_labels[]      = $r['month'];
    $cohort_new[]         = intval($r['new_customers']);
    $cohort_transferred[] = intval($r['transferred_in']);
    $running += intval($r['new_customers']);
    $cohort_cum[]         = $running;
}
$customers_without_created = intval(mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COUNT(*) AS n FROM msp_dim_customer WHERE wefact_created_at IS NULL"))['n']);

// Net-new this year (excluding transfers) vs prior year.
$current_year = date('Y');
$ytd_new = intval(mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COUNT(*) AS n FROM msp_dim_customer
     WHERE YEAR(wefact_created_at) = $current_year AND transferred_from_customer_id IS NULL"))['n']);
$ytd_transferred = intval(mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COUNT(*) AS n FROM msp_dim_customer
     WHERE YEAR(wefact_created_at) = $current_year AND transferred_from_customer_id IS NOT NULL"))['n']);
$prev_year_new = intval(mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COUNT(*) AS n FROM msp_dim_customer
     WHERE YEAR(wefact_created_at) = " . ($current_year - 1) . " AND transferred_from_customer_id IS NULL"))['n']);

// MRR / werkplekken delta vs prior snapshots. We compare the latest snapshot
// against the nearest snapshot >= N days back. NULL when none exists.
function snapshot_totals_on_or_before($mysqli, $date) {
    $r = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT s.snapshot_date,
                SUM(s.mrr_eur) AS mrr,
                SUM(s.workplaces_count) AS wp,
                COUNT(DISTINCT s.customer_id) AS cust
         FROM msp_fact_subscription_snapshot s
         WHERE s.snapshot_date = (
             SELECT MAX(snapshot_date) FROM msp_fact_subscription_snapshot WHERE snapshot_date <= '$date'
         )"));
    return $r && $r['snapshot_date'] ? $r : null;
}
$today_totals    = snapshot_totals_on_or_before($mysqli, $latest_date);
$d7_totals       = snapshot_totals_on_or_before($mysqli, date('Y-m-d', strtotime("$latest_date -7 days")));
$d30_totals      = snapshot_totals_on_or_before($mysqli, date('Y-m-d', strtotime("$latest_date -30 days")));
$d365_totals     = snapshot_totals_on_or_before($mysqli, date('Y-m-d', strtotime("$latest_date -365 days")));

function delta_line($label, $now, $then) {
    if (!$then || $then['snapshot_date'] === $now['snapshot_date']) {
        return "<td>$label</td><td class='text-right text-muted'>—</td><td class='text-right text-muted'>—</td><td class='text-right text-muted'>—</td><td class='small text-muted'>onvoldoende historie</td>";
    }
    $dm = floatval($now['mrr']) - floatval($then['mrr']);
    $dw = intval($now['wp'])    - intval($then['wp']);
    $dc = intval($now['cust'])  - intval($then['cust']);
    $cls = fn($v) => $v > 0 ? 'text-success' : ($v < 0 ? 'text-danger' : 'text-muted');
    $sign = fn($v) => $v > 0 ? '+' : ($v < 0 ? '−' : '±');
    return "<td>$label</td>" .
        "<td class='text-right " . $cls($dm) . "'>" . $sign($dm) . '&nbsp;&euro;&nbsp;' . number_format(abs($dm), 0, ',', '.') . "</td>" .
        "<td class='text-right " . $cls($dw) . "'>" . $sign($dw) . abs($dw) . "</td>" .
        "<td class='text-right " . $cls($dc) . "'>" . $sign($dc) . abs($dc) . "</td>" .
        "<td class='small text-muted'>t.o.v. " . htmlentities($then['snapshot_date']) . "</td>";
}

$cfg = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT config_msp_last_sync_wefact_at, config_msp_last_sync_timeon_at, config_msp_last_sync_freshdesk_at
     FROM settings WHERE company_id = 1 LIMIT 1"));
?>

<!-- KPI tiles -->
<div class="row">
    <div class="col-lg-3 col-6">
        <div class="small-box bg-info">
            <div class="inner">
                <h3><?= number_format($totals['customers']) ?></h3>
                <p>Klanten</p>
            </div>
            <div class="icon"><i class="fas fa-users"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-success">
            <div class="inner">
                <h3>&euro;&nbsp;<?= number_format($totals['mrr_total'], 0, ',', '.') ?></h3>
                <p>MRR per maand</p>
            </div>
            <div class="icon"><i class="fas fa-euro-sign"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-primary">
            <div class="inner">
                <h3><?= number_format($totals['workplaces_total']) ?></h3>
                <p>Werkplekken</p>
            </div>
            <div class="icon"><i class="fas fa-desktop"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-secondary">
            <div class="inner">
                <h3><?= number_format($totals['subs_total']) ?></h3>
                <p>Abonnementsregels</p>
            </div>
            <div class="icon"><i class="fas fa-file-invoice-dollar"></i></div>
        </div>
    </div>
</div>

<!-- Sync status bar -->
<div class="card card-body py-2 mb-3">
    <div class="row small">
        <div class="col-md-4"><strong>WeFact:</strong> <?= $cfg['config_msp_last_sync_wefact_at'] ?: '<span class="text-secondary">never</span>' ?></div>
        <div class="col-md-4"><strong>TimeOn:</strong> <?= $cfg['config_msp_last_sync_timeon_at'] ?: '<span class="text-secondary">never</span>' ?></div>
        <div class="col-md-4"><strong>Freshdesk:</strong> <?= $cfg['config_msp_last_sync_freshdesk_at'] ?: '<span class="text-secondary">never</span>' ?></div>
    </div>
</div>

<div class="row">
    <!-- Top 10 customers by MRR -->
    <div class="col-md-7">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-trophy mr-2"></i>Top 10 klanten — MRR</h3></div>
            <div class="card-body"><div style="position:relative;height:380px;"><canvas id="mspTopMrr"></canvas></div></div>
        </div>
    </div>
    <!-- MRR trend -->
    <div class="col-md-5">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-chart-line mr-2"></i>Totalen over tijd</h3></div>
            <div class="card-body">
                <div style="position:relative;height:380px;"><canvas id="mspTrend"></canvas></div>
                <?php if (count($trend_labels) < 2) { ?>
                    <small class="text-muted">Nog maar één snapshot. Trend bouwt zich op naarmate de sync vaker draait.</small>
                <?php } ?>
            </div>
        </div>
    </div>
</div>

<!-- Growth section -->
<div class="row">
    <div class="col-md-7">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-user-plus mr-2"></i>Nieuwe klanten per maand</h3></div>
            <div class="card-body">
                <div style="position:relative;height:320px;"><canvas id="mspCohort"></canvas></div>
                <?php if ($customers_without_created > 0) { ?>
                    <small class="text-muted"><?= $customers_without_created ?> klant(en) zonder WeFact created-date — niet meegeteld.</small>
                <?php } ?>
            </div>
        </div>
    </div>
    <div class="col-md-5">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-balance-scale mr-2"></i>Delta's</h3></div>
            <div class="card-body p-0">
                <table class="table table-sm table-borderless mb-0">
                    <thead><tr>
                        <th>Periode</th>
                        <th class="text-right">MRR</th>
                        <th class="text-right">WP</th>
                        <th class="text-right">Klanten</th>
                        <th></th>
                    </tr></thead>
                    <tbody>
                        <tr><?= delta_line('7 dagen',   $today_totals, $d7_totals)   ?></tr>
                        <tr><?= delta_line('30 dagen',  $today_totals, $d30_totals)  ?></tr>
                        <tr><?= delta_line('1 jaar',    $today_totals, $d365_totals) ?></tr>
                    </tbody>
                </table>
                <div class="px-3 py-2 small text-muted border-top">
                    Dit jaar nieuw: <strong><?= $ytd_new ?></strong> klanten
                    <?php if ($ytd_transferred > 0) { ?>
                        &nbsp;+&nbsp; <?= $ytd_transferred ?> overgenomen
                    <?php } ?>
                    <?php if ($prev_year_new > 0) { ?>
                        &nbsp;·&nbsp; vorig jaar in totaal: <?= $prev_year_new ?>
                    <?php } ?>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- All customers table -->
<div class="card">
    <div class="card-header py-2">
        <h3 class="card-title mt-2"><i class="fas fa-fw fa-table mr-2"></i>Alle klanten (snapshot <?= htmlentities($latest_date) ?>)</h3>
    </div>
    <div class="card-body p-0">
        <table class="table table-striped table-hover mb-0">
            <thead><tr>
                <th>Klant</th>
                <th class="text-right">MRR</th>
                <th class="text-right">Werkplekken</th>
                <th class="text-right">Abos</th>
                <th class="text-right">€ / werkplek</th>
                <th class="text-center">Actie</th>
            </tr></thead>
            <tbody>
            <?php while ($r = mysqli_fetch_assoc($all)) {
                $mrr = floatval($r['mrr_eur']);
                $wp  = intval($r['workplaces_count']);
                $per_wp = $wp > 0 ? $mrr / $wp : null;
                $cid = intval($r['customer_id']); ?>
                <tr>
                    <td>
                        <?php if (!empty($r['itflow_client_id'])) { ?>
                            <a href="/agent/client_details.php?client_id=<?= intval($r['itflow_client_id']) ?>"><?= nullable_htmlentities($r['customer_name']) ?></a>
                        <?php } else { ?>
                            <?= nullable_htmlentities($r['customer_name']) ?>
                        <?php } ?>
                        <?php if (!empty($r['pred_name'])) { ?>
                            <div><small class="text-info"><i class="fa fa-fw fa-arrow-left mr-1"></i>overgenomen van <?= nullable_htmlentities($r['pred_name']) ?></small></div>
                        <?php } ?>
                        <?php if (!empty($r['succ_name'])) { ?>
                            <div><small class="text-warning"><i class="fa fa-fw fa-arrow-right mr-1"></i>overgedragen aan <?= nullable_htmlentities($r['succ_name']) ?></small></div>
                        <?php } ?>
                    </td>
                    <td class="text-right">&euro;&nbsp;<?= number_format($mrr, 2, ',', '.') ?></td>
                    <td class="text-right"><?= $wp ?: '<span class="text-muted">–</span>' ?></td>
                    <td class="text-right"><?= intval($r['subscription_count']) ?></td>
                    <td class="text-right"><?= $per_wp !== null ? '&euro;&nbsp;' . number_format($per_wp, 0, ',', '.') : '<span class="text-muted">–</span>' ?></td>
                    <td class="text-center">
                        <div class="dropdown dropleft">
                            <button class="btn btn-sm btn-secondary" type="button" data-toggle="dropdown"><i class="fas fa-ellipsis-h"></i></button>
                            <div class="dropdown-menu">
                                <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/msp_metrics/customer_transfer.php?id=<?= $cid ?>">
                                    <i class="fa fa-fw fa-exchange-alt mr-2"></i>Markeer als overgenomen van...
                                </a>
                            </div>
                        </div>
                    </td>
                </tr>
            <?php } ?>
            </tbody>
        </table>
    </div>
</div>

<?php require_once "../includes/footer.php"; ?>

<script>
(function () {
    Chart.defaults.font.family = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
    Chart.defaults.color = '#292b2c';

    var topLabels = <?= json_encode(array_map(fn($l) => mb_strimwidth($l, 0, 32, '…'), $top_labels), JSON_UNESCAPED_UNICODE) ?>;
    var topMrr    = <?= json_encode($top_mrr) ?>;
    var topCtx = document.getElementById('mspTopMrr');
    if (topCtx) new Chart(topCtx, {
        type: 'bar',
        data: {
            labels: topLabels,
            datasets: [{ label: 'MRR (€)', data: topMrr, backgroundColor: '#28a745' }]
        },
        options: {
            indexAxis: 'y',
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { ticks: { callback: v => '€ ' + v.toLocaleString('nl-NL') } } }
        }
    });

    var cohortCtx = document.getElementById('mspCohort');
    if (cohortCtx) new Chart(cohortCtx, {
        data: {
            labels: <?= json_encode($cohort_labels) ?>,
            datasets: [
                { type: 'bar',  label: 'Nieuwe klanten', data: <?= json_encode($cohort_new) ?>,         backgroundColor: '#17a2b8', stack: 'cohort', yAxisID: 'y' },
                { type: 'bar',  label: 'Overgenomen',    data: <?= json_encode($cohort_transferred) ?>, backgroundColor: '#adb5bd', stack: 'cohort', yAxisID: 'y' },
                { type: 'line', label: 'Cumulatief',     data: <?= json_encode($cohort_cum) ?>,         borderColor: '#343a40', backgroundColor: '#343a40', tension: 0.2, yAxisID: 'y2' }
            ]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                y:  { position: 'left',  title: { display: true, text: 'Per maand' }, stacked: true, beginAtZero: true },
                y2: { position: 'right', title: { display: true, text: 'Totaal' },    beginAtZero: true, grid: { drawOnChartArea: false } }
            }
        }
    });

    var trendLabels = <?= json_encode($trend_labels) ?>;
    var trendMrr    = <?= json_encode($trend_mrr) ?>;
    var trendWp     = <?= json_encode($trend_wp) ?>;
    var trendCtx = document.getElementById('mspTrend');
    if (trendCtx) new Chart(trendCtx, {
        type: 'line',
        data: {
            labels: trendLabels,
            datasets: [
                { label: 'MRR (€)',       data: trendMrr, borderColor: '#28a745', backgroundColor: '#28a745', yAxisID: 'y',  tension: 0.2 },
                { label: 'Werkplekken',   data: trendWp,  borderColor: '#007bff', backgroundColor: '#007bff', yAxisID: 'y2', tension: 0.2 }
            ]
        },
        options: {
            maintainAspectRatio: false,
            scales: {
                y:  { position: 'left',  title: { display: true, text: '€ MRR' } },
                y2: { position: 'right', title: { display: true, text: 'Werkplekken' }, grid: { drawOnChartArea: false } }
            }
        }
    });
})();
</script>
