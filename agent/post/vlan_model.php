<?php
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$vlan_number      = intval($_POST['vlan_number'] ?? 0);
$vlan_name        = sanitizeInput($_POST['vlan_name'] ?? '');
$vlan_description = sanitizeInput($_POST['vlan_description'] ?? '');
$vlan_color       = sanitizeInput($_POST['vlan_color'] ?? '#6c757d');
$vlan_network_id  = intval($_POST['vlan_network_id'] ?? 0);

if ($vlan_number < 1 || $vlan_number > 4094) {
    flash_alert('VLAN number must be between 1 and 4094.', 'error');
    redirect();
}
if ($vlan_name === '') {
    flash_alert('VLAN name is required.', 'error');
    redirect();
}
// Light validation on the colour — must be a #rrggbb. Reset to default otherwise.
if (!preg_match('/^#[0-9a-fA-F]{6}$/', $vlan_color)) {
    $vlan_color = '#6c757d';
}
