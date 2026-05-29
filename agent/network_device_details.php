<?php
/*
 * Network-device faceplate. The page is asset-scoped — we want the
 * client sidebar for the asset's client, not the global one. The
 * standard inc_all_client.php expects $_GET['client_id'], so we run a
 * cheap pre-query to derive it from the asset id before pulling the
 * full client-context bootstrap.
 */
require_once $_SERVER['DOCUMENT_ROOT'] . '/config.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/functions.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/check_login.php';

$asset_id = intval($_GET['id'] ?? 0);
$pre = mysqli_fetch_assoc(mysqli_query($mysqli,
    "SELECT asset_client_id FROM assets WHERE asset_id = $asset_id LIMIT 1"));
if (!$pre) {
    require_once "includes/inc_all.php";
    echo "<div class='card card-dark'><div class='card-body'><div class='alert alert-warning'>Asset not found.</div></div></div>";
    require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/footer.php';
    exit;
}
$_GET['client_id'] = intval($pre['asset_client_id']);

require_once "includes/inc_all_client.php";

enforceUserPermission('module_support');

$row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT a.*, c.client_id AS c_id, c.client_name,
           l.location_name
    FROM assets a
    LEFT JOIN clients   c ON c.client_id   = a.asset_client_id
    LEFT JOIN locations l ON l.location_id = a.asset_location_id
    WHERE a.asset_id = $asset_id
      AND a.asset_archived_at IS NULL
    LIMIT 1
"));

if (!$row) {
    echo "<div class='card card-dark'><div class='card-body'><div class='alert alert-warning'>Asset not found.</div></div></div>";
    require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/footer.php';
    exit;
}

$a_name       = nullable_htmlentities($row['asset_name']);
$a_desc       = nullable_htmlentities($row['asset_description']);
$a_type       = nullable_htmlentities($row['asset_type']);
$a_make       = nullable_htmlentities($row['asset_make']);
$a_model      = nullable_htmlentities($row['asset_model']);
$a_uri        = $row['asset_uri'] ? nullable_htmlentities($row['asset_uri']) : '';
$a_phys       = nullable_htmlentities($row['asset_physical_location']);
$a_notes      = nullable_htmlentities($row['asset_notes']);
$a_poe_b      = $row['asset_poe_budget_watts'];
$loc_name     = nullable_htmlentities($row['location_name']);
$client_name  = nullable_htmlentities($row['client_name']);

// All ports of this asset, with VLAN, asset attach, link target.
$ports_q = mysqli_query($mysqli, "
    SELECT p.*,
           av.vlan_number AS access_vlan_number, av.vlan_color AS access_vlan_color, av.vlan_name AS access_vlan_name,
           nv.vlan_number AS native_vlan_number, nv.vlan_color AS native_vlan_color, nv.vlan_name AS native_vlan_name,
           ca.asset_name   AS connected_asset_name,
           ca.asset_type   AS connected_asset_type,
           ca.asset_id     AS connected_asset_id,
           tp.port_number  AS to_port_number,
           tpa.asset_name  AS to_device_name
    FROM asset_ports p
    LEFT JOIN vlans   av ON av.vlan_id = p.port_access_vlan_id
    LEFT JOIN vlans   nv ON nv.vlan_id = p.port_native_vlan_id
    LEFT JOIN assets  ca ON ca.asset_id = p.port_connected_asset_id
    LEFT JOIN asset_ports tp ON tp.port_id = p.port_to_port_id
    LEFT JOIN assets  tpa ON tpa.asset_id = tp.port_device_asset_id
    WHERE p.port_device_asset_id = $asset_id
      AND p.port_archived_at IS NULL
    ORDER BY p.port_number ASC
");
$ports = [];
$used_count = 0;
$poe_used_total = 0;
while ($p = mysqli_fetch_assoc($ports_q)) {
    $ports[] = $p;
    if (!empty($p['port_connected_asset_id']) || !empty($p['port_to_port_id'])) $used_count++;
    if (!empty($p['port_poe_enabled']) && !empty($p['port_poe_watts_used'])) {
        $poe_used_total += floatval($p['port_poe_watts_used']);
    }
}
$total_rendered = count($ports);
$utilization = $total_rendered > 0 ? round($used_count / $total_rendered * 100) : 0;
$poe_pct = ($a_poe_b && $a_poe_b > 0) ? round($poe_used_total / $a_poe_b * 100) : 0;
?>

<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2">
            <i class="fa fa-fw fa-<?= htmlentities(getAssetIcon($row['asset_type'])) ?> mr-2"></i>
            <a class="text-white" href="clients.php?client_id=<?= $client_id ?>"><?= $client_name ?></a>
            &raquo; <?= $a_name ?>
            <small class="badge badge-light ml-2"><?= $a_type ?></small>
        </h3>
        <div class="card-tools">
            <a href="network_devices.php?client_id=<?= $client_id ?>" class="btn btn-outline-light mr-2"><i class="fa fa-fw fa-arrow-left mr-1"></i>Back</a>
            <button type="button" class="btn btn-secondary ajax-modal mr-2" data-modal-url="modals/network_device/ports_generate.php?asset_id=<?= $asset_id ?>&client_id=<?= $client_id ?>"><i class="fa fa-fw fa-plus mr-1"></i>Add ports</button>
            <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/asset/asset_edit.php?id=<?= $asset_id ?>"><i class="fa fa-fw fa-edit mr-1"></i>Edit asset</button>
        </div>
    </div>
    <div class="card-body">

        <div class="row mb-3">
            <div class="col-md-3"><strong>Make / model:</strong> <?= trim($a_make . ' ' . $a_model) ?: '-' ?></div>
            <div class="col-md-3"><strong>Location:</strong> <?= $loc_name ?: '-' ?></div>
            <div class="col-md-3"><strong>Physical:</strong> <?= $a_phys ?: '-' ?></div>
            <div class="col-md-3">
                <?php if ($a_uri) { ?>
                    <strong>Mgmt:</strong> <a href="<?= $a_uri ?>" target="_blank"><?= $a_uri ?></a>
                <?php } ?>
            </div>
        </div>

        <?php if ($a_desc) { ?>
            <p class="text-muted small"><?= $a_desc ?></p>
        <?php } ?>

        <?php if ($total_rendered === 0) { ?>
            <div class="alert alert-info">
                This asset has no network ports yet. Use <strong>Add ports</strong> to generate empty rows you can then label.
            </div>
        <?php } else { ?>
            <div class="row mb-3">
                <div class="col-md-6">
                    <label class="small text-muted mb-1">Port utilization</label>
                    <div class="progress" style="height: 18px;">
                        <div class="progress-bar bg-<?= $utilization > 80 ? 'danger' : ($utilization > 50 ? 'warning' : 'success') ?>"
                             style="width: <?= $utilization ?>%"><?= $used_count ?> / <?= $total_rendered ?> ports used (<?= $utilization ?>%)</div>
                    </div>
                </div>
                <?php if ($a_poe_b > 0) { ?>
                    <div class="col-md-6">
                        <label class="small text-muted mb-1">PoE budget</label>
                        <div class="progress" style="height: 18px;">
                            <div class="progress-bar bg-<?= $poe_pct > 80 ? 'danger' : ($poe_pct > 50 ? 'warning' : 'info') ?>"
                                 style="width: <?= min($poe_pct,100) ?>%"><?= round($poe_used_total) ?> / <?= intval($a_poe_b) ?> W (<?= $poe_pct ?>%)</div>
                        </div>
                    </div>
                <?php } ?>
            </div>

            <hr>

            <!-- Faceplate -->
            <style>
                .pp-faceplate {
                    display: grid;
                    grid-template-columns: repeat(<?= max(8, min(24, ceil($total_rendered / 2))) ?>, 1fr);
                    gap: 4px;
                    background: #1e1e1e;
                    padding: 14px;
                    border-radius: 6px;
                    margin-bottom: 16px;
                }
                .pp-port-cell {
                    aspect-ratio: 1.6 / 1;
                    border-radius: 4px;
                    padding: 6px 6px 4px 6px;
                    cursor: pointer;
                    position: relative;
                    color: #fff;
                    font-size: 0.72rem;
                    line-height: 1;
                    overflow: hidden;
                    box-shadow: inset 0 -2px 0 rgba(0,0,0,0.25);
                    transition: transform 0.08s, box-shadow 0.08s;
                }
                .pp-port-cell:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.4), inset 0 -2px 0 rgba(0,0,0,0.25);
                }
                .pp-port-num { font-weight: 700; font-size: 0.85rem; }
                .pp-port-info { margin-top: 3px; font-size: 0.65rem; opacity: 0.9; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .pp-port-vlan-dot {
                    position: absolute; top: 4px; right: 4px;
                    width: 8px; height: 8px; border-radius: 50%;
                    border: 1px solid rgba(255,255,255,0.6);
                }
                .pp-port-poe::after {
                    content: ''; position: absolute; bottom: 3px; left: 4px;
                    width: 6px; height: 6px; background: #ffc107; border-radius: 50%;
                    box-shadow: 0 0 4px #ffc107;
                }
                .pp-status-up        { background: #28a745; }
                .pp-status-up-empty  { background: #4d8a5f; }
                .pp-status-down      { background: #6c757d; }
                .pp-status-admin     { background: #495057; opacity: 0.6; }
                .pp-status-reserved  { background: #17a2b8; }
                .pp-status-unknown   { background: #343a40; }
                .pp-mode-trunk       { box-shadow: inset 0 0 0 2px #3498db, inset 0 -2px 0 rgba(0,0,0,0.25); }
                .pp-mode-hybrid      { box-shadow: inset 0 0 0 2px #9b59b6, inset 0 -2px 0 rgba(0,0,0,0.25); }
                .pp-uplink-icon { position: absolute; bottom: 2px; right: 4px; opacity: 0.8; font-size: 0.65rem; }
                .pp-legend { display: flex; flex-wrap: wrap; gap: 12px; font-size: 0.78rem; }
                .pp-legend-item { display: flex; align-items: center; gap: 6px; }
                .pp-legend-sample { width: 14px; height: 14px; border-radius: 3px; }
            </style>

            <div class="pp-faceplate">
                <?php foreach ($ports as $p) {
                    $port_id     = intval($p['port_id']);
                    $port_num    = intval($p['port_number']);
                    $mode        = $p['port_mode'];
                    $status      = $p['port_status'];
                    $access_v_n  = $p['access_vlan_number'];
                    $access_v_c  = $p['access_vlan_color'] ?: '#6c757d';
                    $native_v_n  = $p['native_vlan_number'];
                    $native_v_c  = $p['native_vlan_color'] ?: '#6c757d';
                    $asset_name  = $p['connected_asset_name'];
                    $to_dev      = $p['to_device_name'];
                    $to_pnum     = $p['to_port_number'];
                    $poe         = !empty($p['port_poe_enabled']);
                    $is_used     = !empty($p['port_connected_asset_id']) || !empty($p['port_to_port_id']);

                    $bgClass = 'pp-status-unknown';
                    if      ($status === 'up')         $bgClass = $is_used ? 'pp-status-up' : 'pp-status-up-empty';
                    else if ($status === 'down')       $bgClass = 'pp-status-down';
                    else if ($status === 'admin-down') $bgClass = 'pp-status-admin';
                    else if ($status === 'reserved')   $bgClass = 'pp-status-reserved';

                    $modeClass = '';
                    if      ($mode === 'trunk')   $modeClass = 'pp-mode-trunk';
                    else if ($mode === 'hybrid')  $modeClass = 'pp-mode-hybrid';

                    $dotColor = '';
                    if ($mode === 'access' && $access_v_n) $dotColor = $access_v_c;
                    else if (($mode === 'trunk' || $mode === 'hybrid') && $native_v_n) $dotColor = $native_v_c;

                    $tooltip = "Port $port_num";
                    if ($p['port_name'])      $tooltip .= " · " . $p['port_name'];
                    if ($mode !== 'passive')  $tooltip .= " · " . $mode;
                    if ($access_v_n)          $tooltip .= " · VLAN $access_v_n (" . $p['access_vlan_name'] . ")";
                    else if ($native_v_n)     $tooltip .= " · Native VLAN $native_v_n";
                    if ($asset_name)          $tooltip .= "\n→ $asset_name";
                    if ($to_dev)              $tooltip .= "\n→ $to_dev port $to_pnum";
                    ?>
                    <div class="pp-port-cell <?= $bgClass ?> <?= $modeClass ?> <?= $poe ? 'pp-port-poe' : '' ?> ajax-modal"
                         data-modal-url="modals/network_device/port_edit.php?id=<?= $port_id ?>"
                         title="<?= htmlentities($tooltip) ?>">
                        <div class="pp-port-num"><?= $port_num ?></div>
                        <?php if ($asset_name) { ?>
                            <div class="pp-port-info" title="<?= nullable_htmlentities($asset_name) ?>"><?= nullable_htmlentities($asset_name) ?></div>
                        <?php } elseif ($p['port_name']) { ?>
                            <div class="pp-port-info"><?= nullable_htmlentities($p['port_name']) ?></div>
                        <?php } elseif ($access_v_n) { ?>
                            <div class="pp-port-info">V<?= $access_v_n ?></div>
                        <?php } ?>
                        <?php if ($dotColor) { ?>
                            <span class="pp-port-vlan-dot" style="background:<?= htmlentities($dotColor) ?>;"></span>
                        <?php } ?>
                        <?php if ($to_pnum) { ?>
                            <i class="fa fa-link pp-uplink-icon"></i>
                        <?php } ?>
                    </div>
                <?php } ?>
            </div>

            <div class="pp-legend">
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-up"></span> Active &amp; connected</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-up-empty"></span> Up but empty</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-down"></span> Down</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-admin"></span> Admin-down</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-reserved"></span> Reserved</div>
                <div class="pp-legend-item"><span class="pp-legend-sample" style="border:2px solid #3498db;"></span> Trunk</div>
                <div class="pp-legend-item"><span class="pp-legend-sample" style="border:2px solid #9b59b6;"></span> Hybrid</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-up"></span><i class="fa fa-circle" style="color:#ffc107;"></i> PoE</div>
                <div class="pp-legend-item"><span class="pp-legend-sample pp-status-up"></span><i class="fa fa-link"></i> Patch chain</div>
            </div>

            <hr>

            <h5><i class="fa fa-fw fa-list mr-2"></i>Port list</h5>
            <div class="table-responsive">
                <table class="table table-striped table-hover table-sm">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Label</th>
                            <th>Mode</th>
                            <th>VLAN</th>
                            <th>Status</th>
                            <th>Connected to</th>
                            <th>Linked port</th>
                            <th>Cable</th>
                            <th>Notes</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($ports as $p) {
                        $port_id     = intval($p['port_id']);
                        $port_num    = intval($p['port_number']);
                        $access_v_n  = $p['access_vlan_number'];
                        $native_v_n  = $p['native_vlan_number'];
                        $access_v_c  = $p['access_vlan_color'] ?: '#6c757d';
                        $native_v_c  = $p['native_vlan_color'] ?: '#6c757d';
                        $vlan_disp = '-';
                        if ($p['port_mode'] === 'access' && $access_v_n) {
                            $vlan_disp = "<span class='badge' style='background:$access_v_c;color:#fff;'>V$access_v_n</span> " . nullable_htmlentities($p['access_vlan_name']);
                        } elseif (($p['port_mode'] === 'trunk' || $p['port_mode'] === 'hybrid') && $native_v_n) {
                            $vlan_disp = "trunk · native <span class='badge' style='background:$native_v_c;color:#fff;'>V$native_v_n</span>";
                        } elseif ($p['port_mode'] === 'trunk' || $p['port_mode'] === 'hybrid') {
                            $vlan_disp = ucfirst($p['port_mode']);
                        }
                        ?>
                        <tr>
                            <td><strong><?= $port_num ?></strong></td>
                            <td><?= nullable_htmlentities($p['port_name']) ?: '-' ?></td>
                            <td><small><?= htmlentities($p['port_mode']) ?></small></td>
                            <td><?= $vlan_disp ?></td>
                            <td><small><?= htmlentities($p['port_status']) ?></small></td>
                            <td>
                                <?php if ($p['connected_asset_id']) { ?>
                                    <a href="#" class="ajax-modal" data-modal-url="modals/asset/asset_details.php?id=<?= intval($p['connected_asset_id']) ?>">
                                        <?= nullable_htmlentities($p['connected_asset_name']) ?>
                                    </a>
                                <?php } else { ?>-<?php } ?>
                            </td>
                            <td>
                                <?php if ($p['to_device_name']) { ?>
                                    <?= nullable_htmlentities($p['to_device_name']) ?> p<?= intval($p['to_port_number']) ?>
                                <?php } else { ?>-<?php } ?>
                            </td>
                            <td><small><?= nullable_htmlentities($p['port_cable_label']) ?: '-' ?></small></td>
                            <td><small class="text-secondary"><?= nullable_htmlentities($p['port_notes']) ?: '' ?></small></td>
                            <td>
                                <a class="btn btn-sm btn-secondary ajax-modal" href="#" data-modal-url="modals/network_device/port_edit.php?id=<?= $port_id ?>">
                                    <i class="fa fa-edit"></i>
                                </a>
                            </td>
                        </tr>
                    <?php } ?>
                    </tbody>
                </table>
            </div>
        <?php } ?>

        <?php if ($a_notes) { ?>
            <hr><h5>Notes</h5>
            <pre class="bg-light p-2 small" style="white-space: pre-wrap;"><?= $a_notes ?></pre>
        <?php } ?>
    </div>
</div>

<?php require_once "../includes/footer.php"; ?>
