<?php
defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

$name = sanitizeInput($_POST['name']);
$description = sanitizeInput($_POST['description']);
$country = sanitizeInput($_POST['country']);
$address = sanitizeInput($_POST['address']);
$city = sanitizeInput($_POST['city']);
$state = sanitizeInput($_POST['state']);
$zip = sanitizeInput($_POST['zip']);
$phone = preg_replace("/[^0-9]/", '',$_POST['phone']);
$phone_country_code = preg_replace("/[^0-9]/", '',$_POST['phone_country_code']);
$extension = preg_replace("/[^0-9]/", '',$_POST['extension']);
$fax = preg_replace("/[^0-9]/", '',$_POST['fax']);
$fax_country_code = preg_replace("/[^0-9]/", '',$_POST['fax_country_code']);
// Opening hours: per-day fields (hours_open/hours_from/hours_to, index 0 = ma) or a raw string in the stored format
$hours_error = false;
if (isset($_POST['hours_form'])) {
    $week = [];
    $any_open = false;
    for ($i = 0; $i < 7; $i++) {
        if (!empty($_POST['hours_open'][$i])) {
            $from = (string) ($_POST['hours_from'][$i] ?? '');
            $to = (string) ($_POST['hours_to'][$i] ?? '');
            if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $from) || !preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $to) || ($from === $to && $from !== '00:00')) {
                $hours_error = true;
                break;
            }
            $week[$i] = ['from' => $from, 'to' => $to];
            $any_open = true;
        } else {
            $week[$i] = null;
        }
    }
    $hours = $any_open ? formatLocationHours($week) : '';
} else {
    $hours = normalizeLocationHours($_POST['hours'] ?? '');
    $hours_error = $hours === null;
}
if ($hours_error) {
    flash_alert("Openingstijden ongeldig: geef per open dag een begin- en eindtijd op (bijv. ma-vr 08:00-18:00; za-zo dicht).", 'error');
    redirect();
}
$hours = mysqli_real_escape_string($mysqli, $hours);
$notes = sanitizeInput($_POST['notes']);
$contact = intval($_POST['contact'] ?? 0);
$location_primary = intval($_POST['location_primary'] ?? 0);
