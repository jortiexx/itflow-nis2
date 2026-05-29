<?php
require_once '../../../includes/modal_header.php';

$port_id = intval($_GET['id']);
$row = mysqli_fetch_assoc(mysqli_query($mysqli, "
    SELECT p.*, a.asset_client_id, a.asset_name AS device_name
    FROM asset_ports p
    JOIN assets a ON a.asset_id = p.port_device_asset_id
    WHERE p.port_id = $port_id
    LIMIT 1
"));
if (!$row) {
    ob_start();
    echo "<div class='modal-body'><div class='alert alert-danger'>Port not found.</div></div>";
    require_once '../../../includes/modal_footer.php';
    exit;
}
$client_id      = intval($row['asset_client_id']);
$device_name    = nullable_htmlentities($row['device_name']);
$port_number    = intval($row['port_number']);
$port_name      = nullable_htmlentities($row['port_name']);
$port_desc      = nullable_htmlentities($row['port_description']);
$port_type      = nullable_htmlentities($row['port_type']);
$port_mode      = $row['port_mode'];
$port_status    = $row['port_status'];
$port_speed     = $row['port_speed_mbps'];
$port_access_v  = intval($row['port_access_vlan_id']);
$port_native_v  = intval($row['port_native_vlan_id']);
$port_poe_en    = intval($row['port_poe_enabled']);
$port_poe_w     = $row['port_poe_watts_used'];
$port_lacp      = nullable_htmlentities($row['port_lacp_group']);
$port_conn_id   = intval($row['port_connected_asset_id']);
$port_to_id     = intval($row['port_to_port_id']);
$port_cable     = nullable_htmlentities($row['port_cable_label']);
$port_notes     = nullable_htmlentities($row['port_notes']);

enforceClientAccess();

$trunk_vlans_now = [];
$tv_q = mysqli_query($mysqli, "SELECT vlan_id FROM asset_port_trunk_vlans WHERE port_id = $port_id");
while ($tv = mysqli_fetch_assoc($tv_q)) {
    $trunk_vlans_now[] = intval($tv['vlan_id']);
}

ob_start();
?>
<div class="modal-header bg-dark">
    <h5 class="modal-title">
        <i class="fa fa-fw fa-plug mr-2"></i><?= $device_name ?> &mdash; Port <?= $port_number ?>
    </h5>
    <button type="button" class="close text-white" data-dismiss="modal"><span>&times;</span></button>
</div>
<form action="post.php" method="post" autocomplete="off" id="portEditForm">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="hidden" name="port_id" value="<?= $port_id ?>">

    <div class="modal-body">

        <ul class="nav nav-pills nav-justified mb-3">
            <li class="nav-item"><a class="nav-link active" data-toggle="pill" href="#tab-port-general">General</a></li>
            <li class="nav-item"><a class="nav-link" data-toggle="pill" href="#tab-port-vlan">VLAN</a></li>
            <li class="nav-item"><a class="nav-link" data-toggle="pill" href="#tab-port-physical">Physical / PoE</a></li>
            <li class="nav-item"><a class="nav-link" data-toggle="pill" href="#tab-port-chain">Chain</a></li>
        </ul>

        <div class="tab-content">

            <div class="tab-pane fade show active" id="tab-port-general">
                <div class="form-row">
                    <div class="form-group col-md-4">
                        <label>Label / Name</label>
                        <input type="text" class="form-control" name="port_name" value="<?= $port_name ?>" maxlength="200" placeholder="e.g. Gi0/<?= $port_number ?>">
                    </div>
                    <div class="form-group col-md-4">
                        <label>Type</label>
                        <input type="text" class="form-control" name="port_type" value="<?= $port_type ?>" maxlength="200" placeholder="e.g. RJ45, SFP+, fibre">
                    </div>
                    <div class="form-group col-md-4">
                        <label>Status</label>
                        <select class="form-control" name="port_status">
                            <?php foreach (['up'=>'Up','down'=>'Down','admin-down'=>'Admin down','reserved'=>'Reserved','unknown'=>'Unknown'] as $k=>$lbl) {
                                $sel = $port_status === $k ? 'selected' : '';
                                echo "<option $sel value='$k'>$lbl</option>";
                            } ?>
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label>Connected asset</label>
                    <select class="form-control select2" name="port_connected_asset_id">
                        <option value="">- None -</option>
                        <?php
                        $sql_a = mysqli_query($mysqli, "SELECT asset_id, asset_name, asset_type FROM assets WHERE asset_client_id = $client_id AND asset_archived_at IS NULL ORDER BY asset_name ASC");
                        while ($r = mysqli_fetch_assoc($sql_a)) {
                            $aid = intval($r['asset_id']);
                            $alabel = nullable_htmlentities($r['asset_name'] . ' (' . $r['asset_type'] . ')');
                            $sel = $aid === $port_conn_id ? 'selected' : '';
                            echo "<option $sel value='$aid'>$alabel</option>";
                        }
                        ?>
                    </select>
                    <small class="form-text text-muted">The host / device that's physically plugged into this port.</small>
                </div>

                <div class="form-group">
                    <label>Description</label>
                    <input type="text" class="form-control" name="port_description" value="<?= $port_desc ?>" placeholder="e.g. Office WAP / Server bond eth0">
                </div>

                <div class="form-group">
                    <label>Notes</label>
                    <textarea class="form-control" rows="2" name="port_notes"><?= $port_notes ?></textarea>
                </div>
            </div>

            <div class="tab-pane fade" id="tab-port-vlan">
                <div class="form-group">
                    <label>Mode</label>
                    <select class="form-control" name="port_mode" id="portModeSelect">
                        <?php foreach (['access'=>'Access (1 VLAN)','trunk'=>'Trunk (multiple VLANs)','hybrid'=>'Hybrid','passive'=>'Passive (patch-panel, no VLAN)'] as $k=>$lbl) {
                            $sel = $port_mode === $k ? 'selected' : '';
                            echo "<option $sel value='$k'>$lbl</option>";
                        } ?>
                    </select>
                </div>

                <div class="form-group" id="portAccessVlanGroup">
                    <label>Access VLAN</label>
                    <select class="form-control select2" name="port_access_vlan_id">
                        <option value="">- None -</option>
                        <?php
                        $sql_v = mysqli_query($mysqli, "SELECT vlan_id, vlan_number, vlan_name, vlan_color FROM vlans WHERE vlan_client_id = $client_id AND vlan_archived_at IS NULL ORDER BY vlan_number ASC");
                        while ($r = mysqli_fetch_assoc($sql_v)) {
                            $vid = intval($r['vlan_id']);
                            $vlabel = nullable_htmlentities('VLAN ' . $r['vlan_number'] . ' — ' . $r['vlan_name']);
                            $sel = $vid === $port_access_v ? 'selected' : '';
                            echo "<option $sel value='$vid'>$vlabel</option>";
                        }
                        ?>
                    </select>
                </div>

                <div class="form-group" id="portNativeVlanGroup">
                    <label>Native VLAN (untagged on trunk)</label>
                    <select class="form-control select2" name="port_native_vlan_id">
                        <option value="">- None -</option>
                        <?php
                        $sql_v = mysqli_query($mysqli, "SELECT vlan_id, vlan_number, vlan_name FROM vlans WHERE vlan_client_id = $client_id AND vlan_archived_at IS NULL ORDER BY vlan_number ASC");
                        while ($r = mysqli_fetch_assoc($sql_v)) {
                            $vid = intval($r['vlan_id']);
                            $vlabel = nullable_htmlentities('VLAN ' . $r['vlan_number'] . ' — ' . $r['vlan_name']);
                            $sel = $vid === $port_native_v ? 'selected' : '';
                            echo "<option $sel value='$vid'>$vlabel</option>";
                        }
                        ?>
                    </select>
                </div>

                <div class="form-group" id="portTrunkVlanGroup">
                    <label>Trunk-allowed VLANs (multi-select)</label>
                    <select class="form-control select2" name="port_trunk_vlan_ids[]" multiple>
                        <?php
                        $sql_v = mysqli_query($mysqli, "SELECT vlan_id, vlan_number, vlan_name FROM vlans WHERE vlan_client_id = $client_id AND vlan_archived_at IS NULL ORDER BY vlan_number ASC");
                        while ($r = mysqli_fetch_assoc($sql_v)) {
                            $vid = intval($r['vlan_id']);
                            $vlabel = nullable_htmlentities('VLAN ' . $r['vlan_number'] . ' — ' . $r['vlan_name']);
                            $sel = in_array($vid, $trunk_vlans_now, true) ? 'selected' : '';
                            echo "<option $sel value='$vid'>$vlabel</option>";
                        }
                        ?>
                    </select>
                    <small class="form-text text-muted">Empty = "all VLANs allowed".</small>
                </div>
            </div>

            <div class="tab-pane fade" id="tab-port-physical">
                <div class="form-row">
                    <div class="form-group col-md-6">
                        <label>Speed (Mbps)</label>
                        <select class="form-control" name="port_speed_mbps">
                            <option value="">- Auto / unknown -</option>
                            <?php foreach ([10,100,1000,2500,5000,10000,25000,40000,100000] as $s) {
                                $sel = intval($port_speed) === $s ? 'selected' : '';
                                echo "<option $sel value='$s'>" . ($s >= 1000 ? ($s/1000).' Gbps' : $s.' Mbps') . "</option>";
                            } ?>
                        </select>
                    </div>
                    <div class="form-group col-md-3">
                        <label>PoE</label>
                        <select class="form-control" name="port_poe_enabled">
                            <option value="0" <?= !$port_poe_en ? 'selected' : '' ?>>Disabled</option>
                            <option value="1" <?= $port_poe_en ? 'selected' : '' ?>>Enabled</option>
                        </select>
                    </div>
                    <div class="form-group col-md-3">
                        <label>PoE used (W)</label>
                        <input type="number" min="0" max="100" step="0.1" class="form-control" name="port_poe_watts_used" value="<?= $port_poe_w !== null ? htmlentities($port_poe_w) : '' ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label>LACP group / port-channel</label>
                    <input type="text" class="form-control" name="port_lacp_group" value="<?= $port_lacp ?>" maxlength="50" placeholder="e.g. Po1, Bond0">
                </div>
            </div>

            <div class="tab-pane fade" id="tab-port-chain">
                <div class="form-group">
                    <label>Linked port (other end of cable)</label>
                    <select class="form-control select2" name="port_to_port_id">
                        <option value="">- None -</option>
                        <?php
                        $sql_p = mysqli_query($mysqli, "
                            SELECT p.port_id, p.port_number, p.port_name,
                                   a.asset_name AS device_name, a.asset_type AS device_kind
                            FROM asset_ports p
                            JOIN assets a ON a.asset_id = p.port_device_asset_id
                            WHERE a.asset_client_id = $client_id
                              AND a.asset_archived_at IS NULL
                              AND p.port_archived_at IS NULL
                              AND p.port_id <> $port_id
                            ORDER BY a.asset_name, p.port_number
                        ");
                        while ($r = mysqli_fetch_assoc($sql_p)) {
                            $pid = intval($r['port_id']);
                            $plabel = nullable_htmlentities($r['device_name'] . ' — Port ' . $r['port_number'] . ($r['port_name'] ? ' (' . $r['port_name'] . ')' : ''));
                            $sel = $pid === $port_to_id ? 'selected' : '';
                            echo "<option $sel value='$pid'>$plabel</option>";
                        }
                        ?>
                    </select>
                    <small class="form-text text-muted">
                        Records the other end of a patch cable: e.g. patch-panel port 12 → switch port 24.
                        The topology view uses this to draw cable chains between devices.
                    </small>
                </div>

                <div class="form-group">
                    <label>Cable label</label>
                    <input type="text" class="form-control" name="port_cable_label" value="<?= $port_cable ?>" maxlength="100" placeholder="e.g. B12-S24">
                </div>
            </div>

        </div>
    </div>
    <div class="modal-footer">
        <button type="submit" name="edit_port" class="btn btn-primary text-bold"><i class="fa fa-check mr-2"></i>Save</button>
        <button type="button" class="btn btn-light" data-dismiss="modal"><i class="fa fa-times mr-2"></i>Cancel</button>
    </div>
</form>
<script>
(function(){
    function refreshPortVlanVisibility() {
        var mode = document.getElementById('portModeSelect').value;
        document.getElementById('portAccessVlanGroup').style.display = (mode === 'access' || mode === 'hybrid') ? '' : 'none';
        document.getElementById('portNativeVlanGroup').style.display = (mode === 'trunk' || mode === 'hybrid') ? '' : 'none';
        document.getElementById('portTrunkVlanGroup').style.display  = (mode === 'trunk' || mode === 'hybrid') ? '' : 'none';
    }
    document.getElementById('portModeSelect').addEventListener('change', refreshPortVlanVisibility);
    refreshPortVlanVisibility();
})();
</script>
<?php require_once '../../../includes/modal_footer.php'; ?>
