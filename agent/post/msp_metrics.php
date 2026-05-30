<?php
/*
 * ITFlow - POST handler for the MSP Metrics dashboard.
 *
 * Currently handles only the "transferred from" relation between two
 * customers (e.g. holding restructure where an abonnement moves from
 * Zo Kinderopvang to Kiekeboe — that's not net-new growth, it's an
 * in-flight transfer that should be visible as such).
 */
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_msp_customer_transfer'])) {
    validateCSRFToken($_POST['csrf_token']);
    enforceUserPermission('module_reporting', 2);

    $customer_id   = intval($_POST['customer_id']);
    $from_id_raw   = intval($_POST['transferred_from_customer_id'] ?? 0);
    $transferred_at = sanitizeInput($_POST['transferred_at'] ?? '');
    $notes         = sanitizeInput($_POST['transfer_notes'] ?? '');

    if ($customer_id <= 0) {
        flash_alert('Geen geldige klant.', 'error');
        redirect('msp_metrics.php');
    }
    if ($from_id_raw === $customer_id) {
        flash_alert('Een klant kan niet van zichzelf zijn overgenomen.', 'error');
        redirect('msp_metrics.php');
    }

    // 0 means "clear the relationship" — nullable in DB so we can model
    // both "previously was a transfer, now corrected" and "never a transfer".
    if ($from_id_raw > 0) {
        $from_sql  = $from_id_raw;
        $date_sql  = $transferred_at !== '' ? "'" . mysqli_real_escape_string($mysqli, $transferred_at) . "'" : 'NULL';
        $notes_sql = "'" . mysqli_real_escape_string($mysqli, $notes) . "'";
    } else {
        $from_sql = $date_sql = $notes_sql = 'NULL';
    }

    mysqli_query($mysqli, "UPDATE msp_dim_customer SET
        transferred_from_customer_id = $from_sql,
        transferred_at               = $date_sql,
        transfer_notes               = $notes_sql
        WHERE customer_id = $customer_id");

    logAction('MSP Metrics', 'Transfer', "$session_name set transfer relation on customer $customer_id");
    flash_alert('Overdracht-relatie opgeslagen');
    redirect('msp_metrics.php');
}
