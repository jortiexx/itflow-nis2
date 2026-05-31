<?php
/*
 * MSP Metrics date-range filter helper.
 *
 * Reads ?preset / ?from / ?to from the URL, normalises into a (preset,
 * from, to) tuple, and emits a Bootstrap inline form. Used by both the
 * main dashboard and the per-employee drill-down so they share state
 * via the URL query string.
 */

function msp_parse_date_range(): array {
    $preset = $_GET['preset'] ?? 'last30';
    $from   = isset($_GET['from']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['from']) ? $_GET['from'] : null;
    $to     = isset($_GET['to'])   && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['to'])   ? $_GET['to']   : null;
    $today  = date('Y-m-d');

    switch ($preset) {
        case 'month':
            $from = date('Y-m-01'); $to = $today; break;
        case 'prev_month':
            $from = date('Y-m-01', strtotime('first day of last month'));
            $to   = date('Y-m-t',  strtotime('last day of last month'));
            break;
        case 'quarter':
            $q = (int)ceil(date('n') / 3);
            $from = date('Y-') . sprintf('%02d', ($q - 1) * 3 + 1) . '-01';
            $to   = $today;
            break;
        case 'prev_quarter':
            $q = (int)ceil(date('n') / 3) - 1;
            $y = (int)date('Y');
            if ($q < 1) { $q = 4; $y -= 1; }
            $from = sprintf('%04d-%02d-01', $y, ($q - 1) * 3 + 1);
            $to   = date('Y-m-t', strtotime(sprintf('%04d-%02d-01', $y, ($q - 1) * 3 + 3)));
            break;
        case 'year':
            $from = date('Y-01-01'); $to = $today; break;
        case 'prev_year':
            $y = (int)date('Y') - 1;
            $from = "$y-01-01"; $to = "$y-12-31"; break;
        case 'last7':
            $from = date('Y-m-d', strtotime('-7 days')); $to = $today; break;
        case 'last90':
            $from = date('Y-m-d', strtotime('-90 days')); $to = $today; break;
        case 'last365':
            $from = date('Y-m-d', strtotime('-365 days')); $to = $today; break;
        case 'custom':
            // Use whatever was passed in; if missing, fall through to last30.
            if ($from && $to) break;
            // no break — fall through
        case 'last30':
        default:
            $preset = 'last30';
            $from = date('Y-m-d', strtotime('-30 days'));
            $to   = $today;
            break;
    }
    return [$preset, $from, $to];
}

function msp_filter_form(string $preset, string $from, string $to, string $action = ''): string {
    $opts = [
        'last7'        => 'Laatste 7 dagen',
        'last30'       => 'Laatste 30 dagen',
        'last90'       => 'Laatste 90 dagen',
        'last365'      => 'Laatste 365 dagen',
        'month'        => 'Deze maand',
        'prev_month'   => 'Vorige maand',
        'quarter'      => 'Dit kwartaal',
        'prev_quarter' => 'Vorig kwartaal',
        'year'         => 'Dit jaar',
        'prev_year'    => 'Vorig jaar',
        'custom'       => 'Aangepast',
    ];
    $action_e = htmlentities($action);
    $opts_html = '';
    foreach ($opts as $k => $label) {
        $sel = $k === $preset ? 'selected' : '';
        $opts_html .= "<option value=\"$k\" $sel>" . htmlentities($label) . "</option>";
    }
    $disabled = $preset === 'custom' ? '' : 'disabled';
    return <<<HTML
<form class="form-inline mb-3" method="get" action="$action_e">
    <label class="mr-2 small text-muted">Periode:</label>
    <select name="preset" class="form-control form-control-sm mr-2" onchange="
        const cust = this.value === 'custom';
        document.getElementById('msp_from').disabled = !cust;
        document.getElementById('msp_to').disabled   = !cust;
        if (!cust) this.form.submit();
    ">$opts_html</select>
    <input type="date" id="msp_from" name="from" value="$from" class="form-control form-control-sm mr-2" $disabled>
    <input type="date" id="msp_to"   name="to"   value="$to"   class="form-control form-control-sm mr-2" $disabled>
    <button type="submit" class="btn btn-sm btn-primary mr-2">Toepassen</button>
    <span class="small text-muted">Bereik: $from t/m $to</span>
</form>
HTML;
}
