<?php
require_once "includes/inc_all.php";
require_once "includes/msp_date_range.php";

if (!$config_module_enable_msp_metrics) {
    flash_alert('MSP Metrics module is disabled.', 'error');
    redirect('dashboard.php');
}
enforceUserPermission('module_reporting');

[$preset, $from, $to] = msp_parse_date_range();
$from_e = mysqli_real_escape_string($mysqli, $from);
$to_e   = mysqli_real_escape_string($mysqli, $to);

$employee_id = intval($_GET['id'] ?? 0);
$emp = $employee_id > 0 ? mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT employee_id, employee_name FROM msp_dim_employee WHERE employee_id = $employee_id LIMIT 1")) : null;
if (!$emp) {
    flash_alert('Medewerker niet gevonden.', 'error');
    redirect('msp_metrics.php');
}
$emp_name = $emp['employee_name'];

// Summary for this employee in range
$summary = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT COALESCE(SUM(hours_billable), 0)    AS billable,
            COALESCE(SUM(hours_nonbillable), 0) AS nonbillable,
            COUNT(DISTINCT customer_id)         AS klanten,
            COUNT(DISTINCT entry_date)          AS dagen
     FROM msp_fact_hours_daily
     WHERE employee_id = $employee_id
       AND entry_date BETWEEN '$from_e' AND '$to_e'"));
$total_h = floatval($summary['billable']) + floatval($summary['nonbillable']);
$billable_pct = $total_h > 0 ? floatval($summary['billable']) / $total_h * 100 : 0;

// Per-customer breakdown (sorted by billable desc)
$per_customer = mysqli_query($mysqli,
    "SELECT c.customer_id, c.customer_name, c.itflow_client_id,
            SUM(h.hours_billable)    AS billable,
            SUM(h.hours_nonbillable) AS nonbillable
     FROM msp_fact_hours_daily h
     JOIN msp_dim_customer c USING (customer_id)
     WHERE h.employee_id = $employee_id
       AND h.entry_date BETWEEN '$from_e' AND '$to_e'
     GROUP BY c.customer_id
     ORDER BY billable DESC");

// Daily trend
$trend = mysqli_query($mysqli,
    "SELECT entry_date,
            SUM(hours_billable)    AS billable,
            SUM(hours_nonbillable) AS nonbillable
     FROM msp_fact_hours_daily
     WHERE employee_id = $employee_id
       AND entry_date BETWEEN '$from_e' AND '$to_e'
     GROUP BY entry_date
     ORDER BY entry_date");
$trend_labels = []; $trend_b = []; $trend_nb = [];
while ($r = mysqli_fetch_assoc($trend)) {
    $trend_labels[] = $r['entry_date'];
    $trend_b[]      = floatval($r['billable']);
    $trend_nb[]     = floatval($r['nonbillable']);
}
?>

<nav class="mb-3 small">
    <a href="/agent/msp_metrics.php?<?= http_build_query(['preset'=>$preset, 'from'=>$from, 'to'=>$to]) ?>"><i class="fa fa-fw fa-chevron-left mr-1"></i>Terug naar MSP Metrics</a>
</nav>

<h2><i class="fa fa-fw fa-user-clock mr-2"></i><?= nullable_htmlentities($emp_name) ?></h2>

<?= msp_filter_form($preset, $from, $to, '/agent/msp_metrics_employee.php?id=' . $employee_id) ?>

<!-- KPI tiles -->
<div class="row">
    <div class="col-lg-3 col-6">
        <div class="small-box bg-success">
            <div class="inner">
                <h3><?= number_format(floatval($summary['billable']), 1, ',', '.') ?> u</h3>
                <p>Billable</p>
            </div>
            <div class="icon"><i class="fas fa-clock"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-secondary">
            <div class="inner">
                <h3><?= number_format(floatval($summary['nonbillable']), 1, ',', '.') ?> u</h3>
                <p>Non-billable</p>
            </div>
            <div class="icon"><i class="fas fa-clock"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-info">
            <div class="inner">
                <h3><?= number_format($billable_pct, 0) ?>%</h3>
                <p>Billable %</p>
            </div>
            <div class="icon"><i class="fas fa-percent"></i></div>
        </div>
    </div>
    <div class="col-lg-3 col-6">
        <div class="small-box bg-primary">
            <div class="inner">
                <h3><?= intval($summary['klanten']) ?></h3>
                <p>Klanten gewerkt</p>
            </div>
            <div class="icon"><i class="fas fa-users"></i></div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-7">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-chart-line mr-2"></i>Uren per dag</h3></div>
            <div class="card-body"><div style="position:relative;height:320px;"><canvas id="empTrend"></canvas></div></div>
        </div>
    </div>
    <div class="col-md-5">
        <div class="card">
            <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-info-circle mr-2"></i>Samenvatting</h3></div>
            <div class="card-body">
                <p class="mb-1">Periode: <strong><?= htmlentities($from) ?> t/m <?= htmlentities($to) ?></strong></p>
                <p class="mb-1">Dagen met geboekte uren: <strong><?= intval($summary['dagen']) ?></strong></p>
                <p class="mb-1">Totaal uren: <strong><?= number_format($total_h, 1, ',', '.') ?></strong></p>
                <p class="mb-1">Gem. per dag (over werkdagen): <strong><?= intval($summary['dagen']) > 0 ? number_format($total_h / intval($summary['dagen']), 1, ',', '.') : '–' ?> u</strong></p>
            </div>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header py-2"><h3 class="card-title mt-2"><i class="fas fa-fw fa-users mr-2"></i>Urenverdeling per klant</h3></div>
    <div class="card-body p-0">
        <table class="table table-striped table-hover mb-0">
            <thead><tr>
                <th>Klant</th>
                <th class="text-right">Billable</th>
                <th class="text-right">Non-billable</th>
                <th class="text-right">Totaal</th>
                <th class="text-right">% van totaal</th>
            </tr></thead>
            <tbody>
            <?php while ($r = mysqli_fetch_assoc($per_customer)) {
                $b = floatval($r['billable']); $nb = floatval($r['nonbillable']);
                $tot = $b + $nb;
                $pct = $total_h > 0 ? $tot / $total_h * 100 : 0; ?>
                <tr>
                    <td>
                        <?php if (!empty($r['itflow_client_id'])) { ?>
                            <a href="/agent/client_details.php?client_id=<?= intval($r['itflow_client_id']) ?>"><?= nullable_htmlentities($r['customer_name']) ?></a>
                        <?php } else { ?>
                            <?= nullable_htmlentities($r['customer_name']) ?>
                        <?php } ?>
                    </td>
                    <td class="text-right"><?= number_format($b, 2, ',', '.') ?> u</td>
                    <td class="text-right text-muted"><?= number_format($nb, 2, ',', '.') ?> u</td>
                    <td class="text-right"><strong><?= number_format($tot, 2, ',', '.') ?> u</strong></td>
                    <td class="text-right"><?= number_format($pct, 1) ?>%</td>
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
    var ctx = document.getElementById('empTrend');
    if (ctx) new Chart(ctx, {
        data: {
            labels: <?= json_encode($trend_labels) ?>,
            datasets: [
                { type: 'bar', label: 'Billable',     data: <?= json_encode($trend_b)  ?>, backgroundColor: '#28a745', stack: 'h' },
                { type: 'bar', label: 'Non-billable', data: <?= json_encode($trend_nb) ?>, backgroundColor: '#adb5bd', stack: 'h' }
            ]
        },
        options: {
            maintainAspectRatio: false,
            scales: { x: { stacked: true }, y: { stacked: true, title: { display: true, text: 'Uren' } } }
        }
    });
})();
</script>
