<?php

// Network devices = assets with at least one row in asset_ports OR an
// asset_type that is typically a port-bearing network device. We do
// *not* introduce a separate device table — switches, patch panels and
// keystones are assets in itflow, full stop.

$sort = "asset_name";
$order = "ASC";

// Switch-ish asset types we surface here by default. Patch panel is not in
// upstream's default type list, but installs that added the type manually
// will pick up too — we filter on the literal string.
$network_kinds = ['Switch', 'Firewall/Router', 'Access Point', 'Patch Panel', 'Wallbox'];

if (isset($_GET['client_id'])) {
    require_once "includes/inc_all_client.php";
    $client_query = "AND asset_client_id = $client_id";
    $client_url = "client_id=$client_id&";
    if (isset($_GET['archived']) && $_GET['archived'] == 1) {
        $archived = 1;
        $archive_query = "asset_archived_at IS NOT NULL";
    } else {
        $archived = 0;
        $archive_query = "asset_archived_at IS NULL";
    }
} else {
    require_once "includes/inc_client_overview_all.php";
    $client_query = '';
    $client_url = '';
    if (isset($_GET['archived']) && $_GET['archived'] == 1) {
        $archived = 1;
        $archive_query = "(client_archived_at IS NOT NULL OR asset_archived_at IS NOT NULL)";
    } else {
        $archived = 0;
        $archive_query = "(client_archived_at IS NULL AND asset_archived_at IS NULL)";
    }
}

enforceUserPermission('module_support');

// $mysqli is loaded by the include above — build the type-IN clause now.
$kinds_in = "'" . implode("','", array_map(fn($k) => mysqli_real_escape_string($mysqli, $k), $network_kinds)) . "'";

if (!$client_url) {
    if (isset($_GET['client']) && !empty($_GET['client'])) {
        $client_query = 'AND asset_client_id = ' . intval($_GET['client']);
        $client = intval($_GET['client']);
    } else {
        $client = '';
    }
}

$asset_type_filter = '';
if (isset($_GET['kind']) && in_array($_GET['kind'], $network_kinds, true)) {
    $asset_type_filter = $_GET['kind'];
    $client_query .= " AND asset_type = '" . mysqli_real_escape_string($mysqli, $asset_type_filter) . "'";
}

// Include port-count = 0 assets so the user can find an existing asset
// and add ports to it. Show "with ports + the canonical network types".
$type_filter_sql = "(asset_type IN ($kinds_in) OR asset_port_count IS NOT NULL OR EXISTS (SELECT 1 FROM asset_ports WHERE port_device_asset_id = assets.asset_id))";

$sql = mysqli_query(
    $mysqli,
    "SELECT SQL_CALC_FOUND_ROWS assets.*,
            clients.client_id AS c_id, clients.client_name,
            locations.location_name,
            (SELECT COUNT(*) FROM asset_ports WHERE port_device_asset_id = assets.asset_id AND port_archived_at IS NULL) AS port_total,
            (SELECT COUNT(*) FROM asset_ports WHERE port_device_asset_id = assets.asset_id AND port_archived_at IS NULL
                AND (port_connected_asset_id IS NOT NULL OR port_to_port_id IS NOT NULL)) AS port_used
     FROM assets
     LEFT JOIN clients   ON clients.client_id   = assets.asset_client_id
     LEFT JOIN locations ON locations.location_id = assets.asset_location_id
     WHERE $archive_query
       AND $type_filter_sql
       AND (asset_name LIKE '%$q%' OR asset_description LIKE '%$q%' OR asset_make LIKE '%$q%' OR asset_model LIKE '%$q%' OR client_name LIKE '%$q%')
       $access_permission_query
       $client_query
     ORDER BY $sort $order
     LIMIT $record_from, $record_to"
);

$num_rows = mysqli_fetch_row(mysqli_query($mysqli, "SELECT FOUND_ROWS()"));
?>
<div class="card card-dark">
    <div class="card-header py-2">
        <h3 class="card-title mt-2"><i class="fas fa-fw fa-network-wired mr-2"></i>Switches &amp; patches</h3>
        <div class="card-tools">
            <a href="network_topology.php<?= $client_url ? '?client_id=' . intval($client_id) : '' ?>" class="btn btn-outline-light mr-2">
                <i class="fa fa-fw fa-project-diagram mr-1"></i>Topology
            </a>
            <button type="button" class="btn btn-primary ajax-modal" data-modal-url="modals/network_device/ports_generate.php?<?= $client_url ?>">
                <i class="fas fa-plus mr-2"></i>Add ports to an asset
            </button>
        </div>
    </div>
    <div class="card-body">
        <form autocomplete="off">
            <?php if ($client_url) { ?>
                <input type="hidden" name="client_id" value="<?= $client_id ?>">
            <?php } ?>
            <input type="hidden" name="archived" value="<?= $archived ?>">
            <div class="row">
                <div class="col-md-4">
                    <div class="input-group">
                        <input type="search" class="form-control" name="q" value="<?= isset($q) ? stripslashes(nullable_htmlentities($q)) : '' ?>" placeholder="Search devices">
                        <div class="input-group-append">
                            <button class="btn btn-dark"><i class="fa fa-search"></i></button>
                        </div>
                    </div>
                </div>
                <div class="col-md-2">
                    <select class="form-control" name="kind" onchange="this.form.submit()">
                        <option value="">- All types -</option>
                        <?php foreach ($network_kinds as $k) {
                            $sel = $asset_type_filter === $k ? 'selected' : '';
                            echo "<option $sel value='" . htmlentities($k) . "'>" . htmlentities($k) . "</option>";
                        } ?>
                    </select>
                </div>
                <?php if (!$client_url) { ?>
                    <div class="col-md-2">
                        <select class="form-control select2" name="client" onchange="this.form.submit()">
                            <option value="">- All Clients -</option>
                            <?php
                            $sql_clients = mysqli_query($mysqli, "
                                SELECT DISTINCT client_id, client_name
                                FROM clients
                                JOIN assets ON asset_client_id = client_id
                                WHERE $archive_query
                                  AND $type_filter_sql
                                  $access_permission_query
                                ORDER BY client_name ASC
                            ");
                            while ($cf = mysqli_fetch_assoc($sql_clients)) {
                                $sel = $client == $cf['client_id'] ? 'selected' : '';
                                echo "<option $sel value='" . intval($cf['client_id']) . "'>" . nullable_htmlentities($cf['client_name']) . "</option>";
                            }
                            ?>
                        </select>
                    </div>
                <?php } ?>
                <div class="col-md-4">
                    <a href="?<?= $client_url ?>archived=<?= $archived == 1 ? 0 : 1 ?>" class="btn btn-<?= $archived == 1 ? 'primary' : 'default' ?> float-right">
                        <i class="fa fa-fw fa-archive mr-2"></i>Archived
                    </a>
                </div>
            </div>
        </form>
        <hr>
        <div class="table-responsive">
            <table class="table table-striped table-borderless table-hover">
                <thead class="text-dark <?= $num_rows[0] == 0 ? 'd-none' : '' ?>">
                <tr>
                    <th><a class="text-secondary" href="?<?= $url_query_strings_sort ?>&sort=asset_name&order=<?= $disp ?>">Asset <?= $sort == 'asset_name' ? $order_icon : '' ?></a></th>
                    <th>Type</th>
                    <th>Make / Model</th>
                    <th>Location</th>
                    <th>Ports</th>
                    <?php if (!$client_url) { ?>
                        <th>Client</th>
                    <?php } ?>
                    <th class="text-center">Action</th>
                </tr>
                </thead>
                <tbody>
                <?php while ($row = mysqli_fetch_assoc($sql)) {
                    $a_id            = intval($row['asset_id']);
                    $a_name          = nullable_htmlentities($row['asset_name']);
                    $a_desc          = nullable_htmlentities($row['asset_description']);
                    $a_type          = nullable_htmlentities($row['asset_type']);
                    $a_make          = nullable_htmlentities($row['asset_make']);
                    $a_model         = nullable_htmlentities($row['asset_model']);
                    $a_phys          = nullable_htmlentities($row['asset_physical_location']);
                    $loc_name        = nullable_htmlentities($row['location_name']) ?: '-';
                    $row_client_id   = intval($row['c_id']);
                    $row_client_name = nullable_htmlentities($row['client_name']);
                    $port_total      = intval($row['port_total']);
                    $port_used       = intval($row['port_used']);
                    $pct = $port_total > 0 ? round($port_used / $port_total * 100) : 0;
                    ?>
                    <tr>
                        <td>
                            <a class="text-dark" href="network_device_details.php?id=<?= $a_id ?>">
                                <div class="media">
                                    <i class="fa fa-fw fa-2x fa-<?= htmlentities(getAssetIcon($row['asset_type'])) ?> mr-2 text-secondary"></i>
                                    <div class="media-body">
                                        <div><?= $a_name ?></div>
                                        <div><small class="text-secondary"><?= $a_desc ?></small></div>
                                    </div>
                                </div>
                            </a>
                        </td>
                        <td><span class="badge badge-secondary"><?= $a_type ?: '-' ?></span></td>
                        <td><?= trim($a_make . ' ' . $a_model) ?: '-' ?></td>
                        <td><?= $loc_name ?><?php if ($a_phys) { ?><div><small class="text-muted"><?= $a_phys ?></small></div><?php } ?></td>
                        <td>
                            <?php if ($port_total > 0) { ?>
                                <div><small><?= $port_used ?> / <?= $port_total ?></small></div>
                                <div class="progress" style="height:5px;width:100px;">
                                    <div class="progress-bar bg-<?= $pct > 80 ? 'danger' : ($pct > 50 ? 'warning' : 'success') ?>" style="width:<?= $pct ?>%"></div>
                                </div>
                            <?php } else { ?>
                                <small class="text-muted">no ports yet</small>
                            <?php } ?>
                        </td>
                        <?php if (!$client_url) { ?>
                            <td><a href="network_devices.php?client_id=<?= $row_client_id ?>"><?= $row_client_name ?></a></td>
                        <?php } ?>
                        <td>
                            <div class="dropdown dropleft text-center">
                                <button class="btn btn-secondary btn-sm" type="button" data-toggle="dropdown">
                                    <i class="fas fa-ellipsis-h"></i>
                                </button>
                                <div class="dropdown-menu">
                                    <a class="dropdown-item" href="network_device_details.php?id=<?= $a_id ?>"><i class="fa fa-fw fa-eye mr-2"></i>View / faceplate</a>
                                    <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/asset/asset_edit.php?id=<?= $a_id ?>"><i class="fa fa-fw fa-edit mr-2"></i>Edit asset</a>
                                    <a class="dropdown-item ajax-modal" href="#" data-modal-url="modals/network_device/ports_generate.php?asset_id=<?= $a_id ?>&client_id=<?= $row_client_id ?>"><i class="fa fa-fw fa-plus mr-2"></i>Add / regenerate ports</a>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php } ?>
                </tbody>
            </table>
        </div>
        <?php require_once "../includes/filter_footer.php"; ?>
    </div>
</div>
<?php require_once "../includes/footer.php"; ?>
