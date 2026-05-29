<?php
/*
 * ITFlow - GET/POST handler for asset_ports (ports on a network-device asset)
 *
 * Two surface actions:
 *  - generate_asset_ports : bulk-insert N empty port rows on an asset
 *  - edit_port            : update one port's metadata, VLANs, and chain link
 *
 * Ports live in `asset_ports`, FK on assets.asset_id with ON DELETE CASCADE
 * — so archiving / deleting an asset takes its ports with it. We never
 * write to assets here (other than the PoE-budget convenience field).
 */
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['generate_asset_ports'])) {
    validateCSRFToken($_POST['csrf_token']);
    enforceUserPermission('module_support', 2);

    $asset_id = intval($_POST['asset_id']);
    if ($asset_id <= 0) {
        flash_alert('Pick an asset.', 'error');
        redirect();
    }

    $row = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT asset_id, asset_client_id, asset_name FROM assets WHERE asset_id = $asset_id AND asset_archived_at IS NULL LIMIT 1"));
    if (!$row) {
        flash_alert('Asset not found.', 'error');
        redirect();
    }
    $client_id  = intval($row['asset_client_id']);
    $asset_name = sanitizeInput($row['asset_name']);
    enforceClientAccess();

    $port_count = max(0, intval($_POST['port_count'] ?? 0));
    if ($port_count < 1 || $port_count > 512) {
        flash_alert('Port count must be between 1 and 512.', 'error');
        redirect();
    }

    // Optional PoE budget update on the asset itself.
    $poe_raw = $_POST['asset_poe_budget_watts'] ?? '';
    if ($poe_raw !== '') {
        $poe = intval($poe_raw);
        mysqli_query($mysqli, "UPDATE assets SET asset_poe_budget_watts = $poe WHERE asset_id = $asset_id");
    }

    // Find current max port_number so we can append.
    $max_row = mysqli_fetch_assoc(mysqli_query($mysqli,
        "SELECT COALESCE(MAX(port_number), 0) AS max_n FROM asset_ports WHERE port_device_asset_id = $asset_id AND port_archived_at IS NULL"));
    $start = intval($max_row['max_n']) + 1;
    $end   = $start + $port_count - 1;

    $values = [];
    for ($n = $start; $n <= $end; $n++) {
        $values[] = "($n, 'unknown', 'passive', $asset_id)";
    }
    mysqli_query($mysqli, "INSERT INTO asset_ports
        (port_number, port_status, port_mode, port_device_asset_id)
        VALUES " . implode(',', $values));

    // Keep the asset's denormalised port count current.
    mysqli_query($mysqli, "UPDATE assets SET asset_port_count = (
        SELECT COUNT(*) FROM asset_ports WHERE port_device_asset_id = $asset_id AND port_archived_at IS NULL
    ) WHERE asset_id = $asset_id");

    logAction('Asset ports', 'Generate', "$session_name generated ports $start..$end on $asset_name", $client_id, $asset_id);
    flash_alert("Generated <strong>$port_count</strong> port(s) on <strong>$asset_name</strong>");
    redirect("network_device_details.php?id=$asset_id");
}

if (isset($_POST['edit_port'])) {
    validateCSRFToken($_POST['csrf_token']);
    enforceUserPermission('module_support', 2);

    $port_id = intval($_POST['port_id']);
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "
        SELECT p.port_device_asset_id, a.asset_client_id, a.asset_name
        FROM asset_ports p
        JOIN assets a ON a.asset_id = p.port_device_asset_id
        WHERE p.port_id = $port_id LIMIT 1
    "));
    if (!$row) {
        flash_alert('Port not found.', 'error');
        redirect();
    }
    $asset_id   = intval($row['port_device_asset_id']);
    $client_id  = intval($row['asset_client_id']);
    $asset_name = sanitizeInput($row['asset_name']);
    enforceClientAccess();

    $port_name        = sanitizeInput($_POST['port_name'] ?? '');
    $port_description = sanitizeInput($_POST['port_description'] ?? '');
    $port_type        = sanitizeInput($_POST['port_type'] ?? '');
    $port_mode_raw    = $_POST['port_mode'] ?? 'passive';
    $port_mode        = in_array($port_mode_raw, ['access','trunk','hybrid','passive'], true) ? $port_mode_raw : 'passive';
    $port_status_raw  = $_POST['port_status'] ?? 'unknown';
    $port_status      = in_array($port_status_raw, ['up','down','admin-down','reserved','unknown'], true) ? $port_status_raw : 'unknown';
    $port_speed       = $_POST['port_speed_mbps'] ?? '';
    $port_speed_sql   = $port_speed === '' ? 'NULL' : intval($port_speed);
    $port_access_vlan = intval($_POST['port_access_vlan_id'] ?? 0);
    $port_native_vlan = intval($_POST['port_native_vlan_id'] ?? 0);
    $port_poe_en      = !empty($_POST['port_poe_enabled']) ? 1 : 0;
    $port_poe_w_raw   = $_POST['port_poe_watts_used'] ?? '';
    $port_poe_w_sql   = $port_poe_w_raw === '' ? 'NULL' : intval($port_poe_w_raw);
    $port_lacp        = sanitizeInput($_POST['port_lacp_group'] ?? '');
    $port_conn_id     = intval($_POST['port_connected_asset_id'] ?? 0);
    $port_to_id       = intval($_POST['port_to_port_id'] ?? 0);
    $port_cable       = sanitizeInput($_POST['port_cable_label'] ?? '');
    $port_notes       = sanitizeInput($_POST['port_notes'] ?? '');

    // VLAN columns only make sense for the matching mode — null out the
    // others so stale references don't linger after a mode switch.
    if ($port_mode === 'access' || $port_mode === 'hybrid') {
        $access_sql = $port_access_vlan > 0 ? $port_access_vlan : 'NULL';
    } else {
        $access_sql = 'NULL';
    }
    if ($port_mode === 'trunk' || $port_mode === 'hybrid') {
        $native_sql = $port_native_vlan > 0 ? $port_native_vlan : 'NULL';
    } else {
        $native_sql = 'NULL';
    }
    $conn_sql = $port_conn_id > 0 ? $port_conn_id : 'NULL';
    $to_sql   = $port_to_id   > 0 ? $port_to_id   : 'NULL';

    mysqli_query($mysqli, "UPDATE asset_ports SET
        port_name               = '$port_name',
        port_description        = '$port_description',
        port_type               = '$port_type',
        port_mode               = '$port_mode',
        port_status             = '$port_status',
        port_speed_mbps         = $port_speed_sql,
        port_access_vlan_id     = $access_sql,
        port_native_vlan_id     = $native_sql,
        port_poe_enabled        = $port_poe_en,
        port_poe_watts_used     = $port_poe_w_sql,
        port_lacp_group         = '$port_lacp',
        port_connected_asset_id = $conn_sql,
        port_to_port_id         = $to_sql,
        port_cable_label        = '$port_cable',
        port_notes              = '$port_notes'
        WHERE port_id = $port_id");

    // Mirror the patch link onto the other end so the chain is bidirectional.
    // Without this, the topology view would have to look for matches in
    // both directions on every edge.
    if ($port_to_id > 0) {
        mysqli_query($mysqli, "UPDATE asset_ports SET port_to_port_id = $port_id WHERE port_id = $port_to_id");
    }
    // If we cleared our pointer, also clear any lingering inbound pointer to us.
    $other = $port_to_id > 0 ? $port_to_id : 0;
    mysqli_query($mysqli, "UPDATE asset_ports SET port_to_port_id = NULL
        WHERE port_to_port_id = $port_id AND port_id <> $other");

    // Reset and write the trunk-allowed VLAN join rows.
    mysqli_query($mysqli, "DELETE FROM asset_port_trunk_vlans WHERE port_id = $port_id");
    if (($port_mode === 'trunk' || $port_mode === 'hybrid') && !empty($_POST['port_trunk_vlan_ids'])) {
        $rows = [];
        foreach ((array)$_POST['port_trunk_vlan_ids'] as $vid) {
            $vid = intval($vid);
            if ($vid > 0) $rows[] = "($port_id, $vid)";
        }
        if ($rows) {
            mysqli_query($mysqli, "INSERT INTO asset_port_trunk_vlans (port_id, vlan_id) VALUES " . implode(',', $rows));
        }
    }

    logAction('Asset ports', 'Edit port', "$session_name edited $asset_name port id=$port_id", $client_id, $asset_id);
    flash_alert('Port saved');
    redirect("network_device_details.php?id=$asset_id");
}
