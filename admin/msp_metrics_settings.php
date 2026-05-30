<?php
require_once "includes/inc_all_admin.php";

$row = mysqli_fetch_assoc(mysqli_query(
    $mysqli,
    "SELECT config_module_enable_msp_metrics,
            config_msp_wefact_api_key,    config_msp_wefact_api_url,
            config_msp_timeon_api_key,    config_msp_timeon_api_url,
            config_msp_freshdesk_api_key, config_msp_freshdesk_domain,
            config_msp_last_sync_wefact_at,
            config_msp_last_sync_timeon_at,
            config_msp_last_sync_freshdesk_at
     FROM settings
     WHERE company_id = 1
     LIMIT 1"
));

$enabled         = !empty($row['config_module_enable_msp_metrics']);
$wefact_key      = $row['config_msp_wefact_api_key']    ?? '';
$wefact_url      = $row['config_msp_wefact_api_url']    ?? 'https://api.mijnwefact.nl/v2/';
$timeon_key      = $row['config_msp_timeon_api_key']    ?? '';
$timeon_url      = $row['config_msp_timeon_api_url']    ?? 'https://api.timeon.nl/';
$freshdesk_key   = $row['config_msp_freshdesk_api_key'] ?? '';
$freshdesk_dom   = $row['config_msp_freshdesk_domain']  ?? '';
$last_wefact     = $row['config_msp_last_sync_wefact_at'];
$last_timeon     = $row['config_msp_last_sync_timeon_at'];
$last_freshdesk  = $row['config_msp_last_sync_freshdesk_at'];

function fmt_last_sync($v) {
    return $v ? '<span class="text-success">last sync ' . htmlentities($v) . '</span>'
              : '<span class="text-muted">never synced</span>';
}
?>
<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-chart-line mr-2"></i>MSP Metrics</h3>
    </div>
    <div class="card-body">

        <div class="alert alert-info small">
            Pulls subscriptions (WeFact), timesheets (TimeOn) and tickets (Freshdesk) into local
            <code>msp_*</code> tables on a cron schedule. The dashboard at
            <code>/agent/msp_metrics.php</code> reads only from those tables — APIs are never
            queried from the rendering path. Keys live in the <code>settings</code> table; protect
            them with the same care as your database credentials.
        </div>

        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <div class="form-group">
                <label>Status</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-toggle-on"></i></span>
                    </div>
                    <select class="form-control" name="msp_metrics_enabled">
                        <option value="0" <?= $enabled ? '' : 'selected' ?>>Disabled</option>
                        <option value="1" <?= $enabled ? 'selected' : '' ?>>Enabled</option>
                    </select>
                </div>
                <small class="form-text text-muted">
                    When disabled, the sidebar entry and the dashboard page are hidden. Sync cron jobs
                    keep running so historical data continues to accumulate; only the UI is gated.
                </small>
            </div>

            <hr>
            <h5><i class="fa fa-fw fa-file-invoice-dollar mr-2"></i>WeFact <small class="ml-2"><?= fmt_last_sync($last_wefact) ?></small></h5>

            <div class="form-group">
                <label>API URL</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-link"></i></span>
                    </div>
                    <input type="text" class="form-control" name="msp_wefact_api_url"
                           placeholder="https://api.mijnwefact.nl/v2/"
                           value="<?= nullable_htmlentities($wefact_url) ?>">
                </div>
            </div>

            <div class="form-group">
                <label>API Key</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="msp_wefact_api_key"
                           placeholder="<?= $wefact_key ? '(unchanged)' : 'WeFact account → Instellingen → API' ?>"
                           autocomplete="new-password">
                </div>
                <small class="form-text text-muted">Leave blank to keep the existing key.</small>
            </div>

            <hr>
            <h5><i class="fa fa-fw fa-clock mr-2"></i>TimeOn <small class="ml-2"><?= fmt_last_sync($last_timeon) ?></small></h5>

            <div class="form-group">
                <label>API URL</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-link"></i></span>
                    </div>
                    <input type="text" class="form-control" name="msp_timeon_api_url"
                           placeholder="https://api.timeon.nl/"
                           value="<?= nullable_htmlentities($timeon_url) ?>">
                </div>
            </div>

            <div class="form-group">
                <label>API Key</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="msp_timeon_api_key"
                           placeholder="<?= $timeon_key ? '(unchanged)' : 'TimeOn → Beheer → API tokens' ?>"
                           autocomplete="new-password">
                </div>
                <small class="form-text text-muted">Leave blank to keep the existing key.</small>
            </div>

            <hr>
            <h5><i class="fa fa-fw fa-life-ring mr-2"></i>Freshdesk <small class="ml-2"><?= fmt_last_sync($last_freshdesk) ?></small></h5>

            <div class="form-group">
                <label>Domain</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-globe"></i></span>
                    </div>
                    <input type="text" class="form-control" name="msp_freshdesk_domain"
                           placeholder="yourcompany.freshdesk.com"
                           value="<?= nullable_htmlentities($freshdesk_dom) ?>">
                </div>
                <small class="form-text text-muted">Without scheme — just the host. e.g. <code>jict.freshdesk.com</code>.</small>
            </div>

            <div class="form-group">
                <label>API Key</label>
                <div class="input-group">
                    <div class="input-group-prepend">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    </div>
                    <input type="password" class="form-control" name="msp_freshdesk_api_key"
                           placeholder="<?= $freshdesk_key ? '(unchanged)' : 'Freshdesk profile → API key' ?>"
                           autocomplete="new-password">
                </div>
                <small class="form-text text-muted">Leave blank to keep the existing key.</small>
            </div>

            <hr>
            <button type="submit" name="edit_msp_metrics_settings" class="btn btn-primary text-bold">
                <i class="fa fa-check mr-2"></i>Save
            </button>
        </form>

        <hr>
        <h5>itflow client mapping</h5>
        <p class="small text-muted">
            Link MSP customer rows to their itflow client record (by fuzzy name match) so customer
            names in the dashboard become clickable. Re-runnable; only fills empty links.
        </p>
        <form action="/cron/msp_link_itflow_clients.php" method="get">
            <button type="submit" class="btn btn-secondary"><i class="fa fa-fw fa-link mr-2"></i>Run mapping now</button>
        </form>

        <hr>
        <h5>Cron schedule</h5>
        <p class="small text-muted mb-1">Add to root's crontab once on the server (see <code>cron/msp_sync_*.php</code>):</p>
        <pre class="small bg-light p-2 mb-0">
0  2 * * *  /usr/bin/php /var/www/&lt;site&gt;/cron/msp_sync_wefact.php
30 * * * *  /usr/bin/php /var/www/&lt;site&gt;/cron/msp_sync_timeon.php
*/15 * * * * /usr/bin/php /var/www/&lt;site&gt;/cron/msp_sync_freshdesk.php
</pre>
    </div>
</div>
<?php require_once "../includes/footer.php";
