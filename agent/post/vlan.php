<?php
/*
 * ITFlow - GET/POST handler for VLANs
 */
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['add_vlan'])) {
    validateCSRFToken($_POST['csrf_token']);
    enforceUserPermission('module_support', 2);

    require_once 'vlan_model.php';

    $client_id = intval($_POST['client_id']);
    enforceClientAccess();

    $vlan_network_clause = $vlan_network_id > 0 ? $vlan_network_id : 'NULL';

    mysqli_query($mysqli, "INSERT INTO vlans SET
        vlan_number      = $vlan_number,
        vlan_name        = '$vlan_name',
        vlan_description = '$vlan_description',
        vlan_color       = '$vlan_color',
        vlan_network_id  = $vlan_network_clause,
        vlan_client_id   = $client_id");

    $vlan_id = mysqli_insert_id($mysqli);
    logAction('VLAN', 'Create', "$session_name created VLAN $vlan_number ($vlan_name)", $client_id, $vlan_id);
    flash_alert("VLAN <strong>$vlan_number — $vlan_name</strong> created");
    redirect();
}

if (isset($_POST['edit_vlan'])) {
    validateCSRFToken($_POST['csrf_token']);
    enforceUserPermission('module_support', 2);

    require_once 'vlan_model.php';

    $vlan_id   = intval($_POST['vlan_id']);
    $client_id = intval(getFieldById('vlans', $vlan_id, 'vlan_client_id'));
    enforceClientAccess();

    $vlan_network_clause = $vlan_network_id > 0 ? $vlan_network_id : 'NULL';

    mysqli_query($mysqli, "UPDATE vlans SET
        vlan_number      = $vlan_number,
        vlan_name        = '$vlan_name',
        vlan_description = '$vlan_description',
        vlan_color       = '$vlan_color',
        vlan_network_id  = $vlan_network_clause
        WHERE vlan_id = $vlan_id");

    logAction('VLAN', 'Edit', "$session_name edited VLAN $vlan_number ($vlan_name)", $client_id, $vlan_id);
    flash_alert("VLAN <strong>$vlan_number — $vlan_name</strong> updated");
    redirect();
}

if (isset($_GET['archive_vlan'])) {
    validateCSRFToken($_GET['csrf_token']);
    enforceUserPermission('module_support', 2);
    $vlan_id = intval($_GET['archive_vlan']);
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT vlan_name, vlan_client_id FROM vlans WHERE vlan_id = $vlan_id"));
    $vlan_name = sanitizeInput($row['vlan_name']);
    $client_id = intval($row['vlan_client_id']);
    enforceClientAccess();
    mysqli_query($mysqli, "UPDATE vlans SET vlan_archived_at = NOW() WHERE vlan_id = $vlan_id");
    logAction('VLAN', 'Archive', "$session_name archived VLAN $vlan_name", $client_id, $vlan_id);
    flash_alert("VLAN <strong>$vlan_name</strong> archived", 'error');
    redirect();
}

if (isset($_GET['restore_vlan'])) {
    validateCSRFToken($_GET['csrf_token']);
    enforceUserPermission('module_support', 2);
    $vlan_id = intval($_GET['restore_vlan']);
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT vlan_name, vlan_client_id FROM vlans WHERE vlan_id = $vlan_id"));
    $vlan_name = sanitizeInput($row['vlan_name']);
    $client_id = intval($row['vlan_client_id']);
    enforceClientAccess();
    mysqli_query($mysqli, "UPDATE vlans SET vlan_archived_at = NULL WHERE vlan_id = $vlan_id");
    logAction('VLAN', 'Restore', "$session_name restored VLAN $vlan_name", $client_id, $vlan_id);
    flash_alert("VLAN <strong>$vlan_name</strong> restored");
    redirect();
}

if (isset($_GET['delete_vlan'])) {
    validateCSRFToken($_GET['csrf_token']);
    enforceUserPermission('module_support', 3);
    $vlan_id = intval($_GET['delete_vlan']);
    $row = mysqli_fetch_assoc(mysqli_query($mysqli, "SELECT vlan_name, vlan_client_id FROM vlans WHERE vlan_id = $vlan_id"));
    $vlan_name = sanitizeInput($row['vlan_name']);
    $client_id = intval($row['vlan_client_id']);
    enforceClientAccess();
    mysqli_query($mysqli, "DELETE FROM vlans WHERE vlan_id = $vlan_id");
    logAction('VLAN', 'Delete', "$session_name deleted VLAN $vlan_name", $client_id);
    flash_alert("VLAN <strong>$vlan_name</strong> deleted", 'error');
    redirect();
}
